#!/usr/bin/env python3
import argparse
import smtplib
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class Result:
    ok: bool
    stage: str
    message: str
    tls: Optional[str] = None
    cipher: Optional[str] = None
    server: Optional[str] = None


def parse_host_port(s: str, default_port: int) -> Tuple[str, int]:
    if s.count(":") == 0:
        return s, default_port
    host, port_s = s.rsplit(":", 1)
    return host, int(port_s)


def tls_details(sock) -> Tuple[Optional[str], Optional[str]]:
    try:
        if hasattr(sock, "version"):
            v = sock.version()
        else:
            v = None
        if hasattr(sock, "cipher"):
            c = sock.cipher()
            cipher = c[0] if c else None
        else:
            cipher = None
        return v, cipher
    except Exception:
        return None, None


def test_smtp(host: str, port: int, use_ssl: bool, use_starttls: bool, user: str, password: str,
              timeout: float, debug: bool, allow_insecure: bool) -> Result:

    context = ssl.create_default_context()
    if allow_insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        if use_ssl:
            client = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context)
        else:
            client = smtplib.SMTP(host=host, port=port, timeout=timeout)
    except socket.gaierror as e:
        return Result(False, "connect", f"DNS/hostname lookup failed: {e}")
    except (ConnectionRefusedError, TimeoutError, socket.timeout) as e:
        return Result(False, "connect", f"Connection failed: {type(e).__name__}: {e}")
    except ssl.SSLError as e:
        return Result(False, "tls", f"TLS handshake failed (implicit SSL): {e}")
    except Exception as e:
        return Result(False, "connect", f"Unexpected connection error: {type(e).__name__}: {e}")

    try:
        if debug:
            client.set_debuglevel(1)

        code, banner = client.noop()
        client.ehlo_or_helo_if_needed()

        tls_v = None
        cipher = None

        if use_starttls:
            try:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                tls_v, cipher = tls_details(client.sock)
            except smtplib.SMTPNotSupportedError as e:
                client.quit()
                return Result(False, "tls", f"STARTTLS not supported by server: {e}")
            except ssl.SSLCertVerificationError as e:
                client.quit()
                return Result(False, "tls", f"Certificate verification failed during STARTTLS: {e}")
            except ssl.SSLError as e:
                client.quit()
                return Result(False, "tls", f"STARTTLS negotiation failed: {e}")

        if use_ssl:
            tls_v, cipher = tls_details(client.sock)

        try:
            client.login(user, password)
        except smtplib.SMTPAuthenticationError as e:
            code = getattr(e, "smtp_code", None)
            err = getattr(e, "smtp_error", b"")
            msg = err.decode(errors="replace") if isinstance(err, (bytes, bytearray)) else str(err)
            client.quit()
            return Result(
                False,
                "auth",
                f"Authentication failed (SMTP {code}): {msg}".strip(),
                tls=tls_v,
                cipher=cipher,
                server=f"{host}:{port}",
            )
        except smtplib.SMTPException as e:
            client.quit()
            return Result(False, "auth", f"SMTP auth error: {type(e).__name__}: {e}", tls=tls_v, cipher=cipher, server=f"{host}:{port}")

        client.quit()
        return Result(True, "ok", "Authenticated successfully.", tls=tls_v, cipher=cipher, server=f"{host}:{port}")

    except ssl.SSLCertVerificationError as e:
        try:
            client.quit()
        except Exception:
            pass
        return Result(False, "tls", f"Certificate verification failed: {e}")
    except smtplib.SMTPException as e:
        try:
            client.quit()
        except Exception:
            pass
        return Result(False, "smtp", f"SMTP protocol error: {type(e).__name__}: {e}")
    except Exception as e:
        try:
            client.quit()
        except Exception:
            pass
        return Result(False, "unknown", f"Unexpected error: {type(e).__name__}: {e}")


def main():
    p = argparse.ArgumentParser(description="Simple SMTP auth tester (SSL or STARTTLS).")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ssl", action="store_true", help="Use implicit TLS (SMTPS).")
    mode.add_argument("--startls", action="store_true", help="Use STARTTLS upgrade.")

    p.add_argument("--smtp", required=True, help="SMTP server as host or host:port")
    p.add_argument("--user", required=True, help="Username")
    p.add_argument("--pass", dest="password", required=True, help="Password")
    p.add_argument("--timeout", type=float, default=10.0, help="Socket timeout seconds (default 10)")
    p.add_argument("--debug", action="store_true", help="Enable smtplib debug output")
    p.add_argument("--insecure", action="store_true", help="Disable TLS cert validation (use only for troubleshooting)")

    args = p.parse_args()

    default_port = 465 if args.ssl else 587
    host, port = parse_host_port(args.smtp, default_port)

    res = test_smtp(
        host=host,
        port=port,
        use_ssl=args.ssl,
        use_starttls=args.startls,
        user=args.user,
        password=args.password,
        timeout=args.timeout,
        debug=args.debug,
        allow_insecure=args.insecure,
    )

    status = "OK" if res.ok else "FAIL"
    print(f"[{status}] stage={res.stage}")
    print(f"  server: {res.server or f'{host}:{port}'}")
    if res.tls or res.cipher:
        print(f"  tls: {res.tls or 'none'}")
        print(f"  cipher: {res.cipher or 'none'}")
    print(f"  message: {res.message}")

    sys.exit(0 if res.ok else 2)


if __name__ == "__main__":
    main()
