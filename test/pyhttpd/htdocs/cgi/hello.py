#!/usr/bin/env python3
import json
import os

data = {
    "https": os.getenv('HTTPS', ''),
    "host": os.getenv('SERVER_NAME', ''),
    "protocol": os.getenv('SERVER_PROTOCOL', ''),
    "ssl_protocol": os.getenv('SSL_PROTOCOL', ''),
    "h2": os.getenv('HTTP2', ''),
    "h2push": os.getenv('H2PUSH', ''),
    "REMOTE_USER": os.getenv('REMOTE_USER', ''),
}

print("Content-Type: application/json")
print()
print(json.JSONEncoder().encode(data))
