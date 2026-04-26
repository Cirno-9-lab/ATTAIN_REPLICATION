import http.server
import os
import socketserver
import random

PORT = 8080
LOG_FILE = f'/home/xinweimao/alv_evaluate/myResearch/workspace/code/PoCEmpirical/reproduce/servers/attack/log.txt'

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        request_id = ''.join(random.choices('0123456789abcdef', k=6))
        log_line = f"[{request_id}] {self.requestline} {code}"
        with open(LOG_FILE, 'a') as f:
            f.write(log_line + '\n')
        super().log_request(code, size)

with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
