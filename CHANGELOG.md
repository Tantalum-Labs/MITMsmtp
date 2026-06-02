# Changelog (Tantalum Labs fork)

This repository is a fork of MITMsmtp by Robin Meis (upstream: https://github.com/RobinMeis/MITMsmtp) and is maintained by Tantalum Labs.

## Unreleased

### Added
- Optional built-in DNS responder (`MITMsmtp/DNSServer.py`) with CLI flags in `MITMsmtp/MITMsmtp.py` (`--enable-dns`, `--dns-port`, `--dns-ip`, `--print-dns`).
- Optional rogue SMB server (`MITMsmtp/SMBServer.py`) that captures NTLM credentials (NetNTLMv1/NetNTLMv2 hashes) from SMB clients such as printers/scanners using "Scan to SMB". CLI flags in `MITMsmtp/MITMsmtp.py` (`--enable-smb`, `--smb-port`, `--smb-challenge`, `--smb-target-name`, `--smb-force-lm-downgrade`, `--smb-log`, `--print-smb`). Captured hashes are printed in a hashcat-crackable format (mode 5500/5600) and can be appended to `smb_credentials.log`.
- `--smb-force-lm-downgrade` advertises a downgraded NTLM challenge (no extended session security / target info) to force clients into a legacy LMv1/NTLMv1 response, capturing the weaker LM hash.
- NTLM relay binary detection now also searches the running interpreter's bin directory (active virtualenv), `$VIRTUAL_ENV/bin`, `~/.local/bin` and the Debian/Kali impacket examples directory, so a pip-installed `ntlmrelayx.py` in a venv is found even when `sudo` strips the venv from `PATH`. Resolved `.py` scripts are launched with the current Python interpreter (handles venvs and non-executable example copies), and the not-found error explains the sudo/venv workaround.
- If `ntlmrelayx` exits immediately on launch (e.g. a `SyntaxError` because the launching Python is too old to parse a newer `ntlmrelayx.py` under sudo, or impacket isn't importable by that interpreter), the relay now reports a clear diagnosis and the venv-Python workaround instead of leaving a bare traceback.
- Optional NTLM relay mode (`MITMsmtp/relay.py`) that delegates live relaying to impacket's `ntlmrelayx`. CLI flags in `MITMsmtp/MITMsmtp.py` (`--relay`, `--relay-target`, `--relay-targets-file`, `--relay-no-smb2support`, `--relay-ip`, `--relay-socks`, `--relay-output-prefix`, `--relay-extra`, `--relay-bin`, `--relay-dry-run`). impacket is an optional dependency (`pip install MITMsmtp[relay]`); `--relay` is mutually exclusive with `--enable-smb` because ntlmrelayx owns port 445. `ntlmrelayx` is auto-detected on PATH as `ntlmrelayx.py`, `ntlmrelayx` or `impacket-ntlmrelayx` (the Kali/Parrot/Debian `impacket-scripts` name), or set explicitly with `--relay-bin`.
- Helper script `MITMsmtp/smtp_test.py` for validating STARTTLS/SMTPS authentication (`--ssl` / `--startls`) and reporting TLS details.

### Fixed
- Make the new DNS/SMB/relay flags reachable from the installed `MITMsmtp` command and `python3 -m MITMsmtp`. Previously these only worked via `python3 MITMsmtp/MITMsmtp.py`, so `MITMsmtp --relay` (and `--enable-smb`/`--enable-dns`) failed with "unrecognized arguments", and `python3 -m MITMsmtp` errored on import. The package entry point now routes to the full-featured runner; the original SMTP-only CLI is preserved as `MITMsmtp-legacy` / `python3 -m MITMsmtp.legacy`. `MITMsmtp/MITMsmtp.py` now uses import fallbacks so it works both as a script and as a package module.
- Avoid `UnicodeDecodeError` by reading client input in binary mode and decoding safely (`MITMsmtp/SMTPHandler.py`).
- Detect likely TLS handshakes on a plaintext SMTP socket and emit a clearer error (`MITMsmtp/SMTPHandler.py`).
- Handle `QUIT` cleanly without stack traces (`MITMsmtp/SMTPHandler.py`).
- Send `235 2.7.0 Authentication successful` from the fork auth handlers so clients proceed to `MAIL FROM` (`MITMsmtp/AuthHandler.py`).
- Tolerate clients that try multiple `AUTH` methods before sending `MAIL FROM` (`MITMsmtp/SMTPHandler.py`).
- Improve parsing of `MAIL FROM:` and `RCPT TO:` variations (`MITMsmtp/SMTPHandler.py`).

### Changed
- The fork runner `MITMsmtp/MITMsmtp.py` defaults to port 587; the legacy packaged CLI (`MITMsmtp/__main__.py` / `MITMsmtp` entrypoint) still defaults to 8587.

