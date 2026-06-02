#!/usr/bin/env python3

"""
Package entry point for MITMsmtp.

This routes `python3 -m MITMsmtp` and the installed `MITMsmtp` console command
to the full-featured Tantalum Labs runner (SMTP capture plus the optional DNS
responder, SMB credential capture and NTLM relay modes).

The original SMTP-only command line interface is preserved as
`MITMsmtp.legacy` (run it with `python3 -m MITMsmtp.legacy` or the
`MITMsmtp-legacy` console command).
"""

from MITMsmtp.MITMsmtp import main

if __name__ == "__main__":
    main()
