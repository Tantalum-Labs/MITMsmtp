#!/usr/bin/env python3

import base64
import re

class AuthHandler:
    """Handles SMTP authentication methods"""
    
    def toString(self):
        """Return supported authentication methods"""
        return "PLAIN LOGIN"
    
    def matchMethod(self, line):
        """Match authentication method and return appropriate handler"""
        if line.upper().startswith("AUTH PLAIN"):
            return PlainAuth
        elif line.upper().startswith("AUTH LOGIN"):
            return LoginAuth
        else:
            return None

class PlainAuth:
    """Handles PLAIN authentication (RFC 4616)"""
    
    def __init__(self, handler, line):
        self.handler = handler
        self.username = ""
        self.password = ""
        self._decode_plain_auth(line)
    
    def _decode_plain_auth(self, line):
        """Decode PLAIN authentication data"""
        try:
            # Extract base64 encoded data from "AUTH PLAIN <base64data>"
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                # Inline format: AUTH PLAIN <base64data>
                auth_data = parts[2]
            else:
                # Two-step format: AUTH PLAIN followed by base64 data on next line
                self.handler.writeLine("334 ")  # Request auth data
                auth_data = self.handler.readLine()
            
            # Decode base64; credentials are often ASCII but may be UTF-8.
            decoded = base64.b64decode(auth_data).decode('utf-8', errors='replace')
            
            # PLAIN format: [authzid]\0username\0password
            auth_parts = decoded.split('\0')
            
            if len(auth_parts) == 3:
                # Format: authzid\0username\0password
                authzid, username, password = auth_parts
                self.username = username
                self.password = password
            elif len(auth_parts) == 2:
                # Format: username\0password
                username, password = auth_parts
                self.username = username
                self.password = password
            else:
                raise ValueError("Invalid PLAIN auth format")

            # Signal auth success so the client continues with MAIL FROM/RCPT TO.
            self.handler.writeLine("235 2.7.0 Authentication successful")
                 
        except Exception as e:
            print(f"[AUTH ERROR] Failed to decode PLAIN auth: {e}")
            self.username = "DECODE_ERROR"
            self.password = "DECODE_ERROR"
            # Still accept to keep the SMTP flow going for capture purposes.
            self.handler.writeLine("235 2.7.0 Authentication successful")
    
    def getUsername(self):
        return self.username
    
    def getPassword(self):
        return self.password

class LoginAuth:
    """Handles LOGIN authentication"""
    
    def __init__(self, handler, line):
        self.handler = handler
        self.username = ""
        self.password = ""
        self._handle_login_auth()
    
    def _handle_login_auth(self):
        """Handle LOGIN authentication process"""
        try:
            # Send Username prompt
            self.handler.writeLine("334 VXNlcm5hbWU6")  # Base64 for "Username:"
            username_line = self.handler.readLine()
            self.username = base64.b64decode(username_line).decode('utf-8', errors='replace')
             
            # Send Password prompt
            self.handler.writeLine("334 UGFzc3dvcmQ6")  # Base64 for "Password:"
            password_line = self.handler.readLine()
            self.password = base64.b64decode(password_line).decode('utf-8', errors='replace')

            # Signal auth success so the client continues with MAIL FROM/RCPT TO.
            self.handler.writeLine("235 2.7.0 Authentication successful")
             
        except Exception as e:
            print(f"[AUTH ERROR] Failed to handle LOGIN auth: {e}")
            self.username = "DECODE_ERROR"
            self.password = "DECODE_ERROR"
            # Still accept to keep the SMTP flow going for capture purposes.
            self.handler.writeLine("235 2.7.0 Authentication successful")
    
    def getUsername(self):
        return self.username
    
    def getPassword(self):
        return self.password
