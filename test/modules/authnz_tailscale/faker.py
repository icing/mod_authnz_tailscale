import json
import os
import re
import socket
from threading import Thread


class TailscaleFaker:

    def __init__(self, env, path):
        self.env = env
        self._uds_path = path
        self._done = False
        self.socket = None
        self.thread = None
        self.whois = None

    def set_whois(self, data):
        self.whois = data

    def start(self):
        def process(me):
            me.socket.listen(1)
            me.process()

        try:
            os.unlink(self._uds_path)
        except OSError:
            if os.path.exists(self._uds_path):
                raise
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(self._uds_path)
        self.thread = Thread(target=process, daemon=True, args=[self])
        self.thread.start()

    def stop(self):
        self._done = True
        self.socket.close()

    def send_error(self, c, status, reason):
        c.sendall(f"""HTTP/1.1 {status} {reason}\r
Server: TailscaleFaker\r
Content-Length: 0\r
Connection: close\r
\r
""".encode())

    def send_data(self, c, ctype: str, data: bytes):
        c.sendall(f"""HTTP/1.1 200 OK\r
Server: TailscaleFaker\r
Content-Type: {ctype}\r
Content-Length: {len(data)}\r
Connection: close\r
\r
""".encode() + data)

    def send_json(self, c, json_data):
        data = json.JSONEncoder().encode(json_data).encode()
        self.send_data(c, 'text/json', data)

    def process(self):
        # a http server written on a sunny afternooon
        while self._done is False:
            try:
                c, client_address = self.socket.accept()
                try:
                    data = c.recv(1024)
                    lines = data.decode().splitlines()
                    m = re.match(r'^(?P<method>\w+)\s+(?P<uri>\S+)\s+HTTP/1.1', lines[0])
                    if m is None:
                        self.send_error(c, 400, "Bad Request")
                        continue
                    uri = m.group('uri')
                    m = re.match(r'/localapi/v0/whois\?addr=(?P<addr>\w+)', uri)
                    if m is None:
                        self.send_error(c, 404, "Not Found")
                        continue
                    if self.whois is None:
                        self.send_error(c, 404, "Not Found")
                        continue
                    self.send_json(c, self.whois)
                finally:
                    c.close()

            except ConnectionAbortedError:
                self._done = True
