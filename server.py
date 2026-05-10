from http.server import HTTPServer, BaseHTTPRequestHandler
import json, subprocess, os

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass  # silence logs

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        if self.path == '/make-pcap':
            length = int(self.headers['Content-Length'])
            body = json.loads(self.rfile.read(length))
            binary = body.get('binary', '')
            save_path = body.get('path', os.path.join(os.path.expanduser('~'), 'Desktop', 'packet.pcap'))
            
            # Run pcapmaker with input piped and custom output path
            result = subprocess.run(
                ['python', 'pcapmaker.py'],
                input=binary,
                capture_output=True,
                text=True
            )

            pcap_bytes = None
            if result.returncode == 0 and os.path.exists('packet.pcap'):
                with open('packet.pcap', 'rb') as f:
                    import base64
                    pcap_bytes = base64.b64encode(f.read()).decode()
                os.remove('packet.pcap')

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                'success': pcap_bytes is not None,
                'bytes': pcap_bytes,
                'error': result.stderr,
            }).encode())

HTTPServer(('localhost', 7432), Handler).serve_forever()