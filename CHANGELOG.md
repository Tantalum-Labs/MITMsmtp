# Changelog (Tantalum Labs fork)

This repository is a fork of MITMsmtp by Robin Meis (upstream: https://github.com/RobinMeis/MITMsmtp) and is maintained by Tantalum Labs.

## Unreleased

### Added
- Optional built-in DNS responder (`MITMsmtp/DNSServer.py`) with CLI flags in `MITMsmtp/MITMsmtp.py` (`--enable-dns`, `--dns-port`, `--dns-ip`, `--print-dns`).
- Helper script `MITMsmtp/smtp_test.py` for validating STARTTLS/SMTPS authentication (`--ssl` / `--startls`) and reporting TLS details.

### Fixed
- Avoid `UnicodeDecodeError` by reading client input in binary mode and decoding safely (`MITMsmtp/SMTPHandler.py`).
- Detect likely TLS handshakes on a plaintext SMTP socket and emit a clearer error (`MITMsmtp/SMTPHandler.py`).
- Handle `QUIT` cleanly without stack traces (`MITMsmtp/SMTPHandler.py`).
- Send `235 2.7.0 Authentication successful` from the fork auth handlers so clients proceed to `MAIL FROM` (`MITMsmtp/AuthHandler.py`).
- Tolerate clients that try multiple `AUTH` methods before sending `MAIL FROM` (`MITMsmtp/SMTPHandler.py`).
- Improve parsing of `MAIL FROM:` and `RCPT TO:` variations (`MITMsmtp/SMTPHandler.py`).

### Changed
- The fork runner `MITMsmtp/MITMsmtp.py` defaults to port 587; the legacy packaged CLI (`MITMsmtp/__main__.py` / `MITMsmtp` entrypoint) still defaults to 8587.

