#!/usr/bin/env python3
"""Simple File Manager — real app target for WAF testing"""
import os, json, urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

ROOT = os.path.expanduser("~/fileshare")

class FMHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path, query = urllib.parse.unquote(p.path), urllib.parse.parse_qs(p.query)
        
        if path == '/api/list':
            d = query.get('dir', [''])[0]
            sp = os.path.normpath(os.path.join(ROOT, d))
            if not sp.startswith(ROOT): return self.send_error(403, "Traversal blocked")
            items = []
            for f in os.listdir(sp):
                fp = os.path.join(sp, f)
                items.append({'name':f,'size':os.path.getsize(fp),'type':'dir' if os.path.isdir(fp) else 'file',
                    'modified': datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()})
            self.send_json({'path':d,'items':items}); return
        
        if path.startswith('/api/read/'):
            sp = os.path.normpath(os.path.join(ROOT, urllib.parse.unquote(path[10:])))
            if not sp.startswith(ROOT): return self.send_error(403)
            with open(sp,'rb') as f: self.send_binary(f.read()); return
        
        fp = os.path.normpath(os.path.join(ROOT, path.lstrip('/')))
        if not fp.startswith(ROOT): return self.send_error(403)
        if os.path.isdir(fp): self.send_html(self._index(fp, path))
        else: super().do_GET()

    def _index(self, dp, up):
        rows = []
        for f in sorted(os.listdir(dp)):
            fp = os.path.join(dp, f)
            ic = '📁' if os.path.isdir(fp) else '📄'
            sz = os.path.getsize(fp)
            szs = f"{sz:,}B" if sz<1024 else f"{sz/1024:.1f}KB"
            rows.append(f'<tr><td>{ic} <a href="{up.rstrip("/")}/{f}">{f}</a></td><td>{szs}</td></tr>')
        return f"""<!DOCTYPE html><html><head>
<title>jarsWAF Test</title><meta charset="utf-8"><style>
body{{font-family:-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}}
h1{{color:#38bdf8}} table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:8px;border-bottom:1px solid #334155;color:#94a3b8}}
td{{padding:8px;border-bottom:1px solid #1e293b}}
a{{color:#60a5fa;text-decoration:none}}
.path{{color:#64748b;margin-bottom:16px}}
</style></head><body>
<h1>📂 jarsWAF Test File Manager</h1>
<div class="path">{up or '/'}</div>
<table><tr><th>Name</th><th>Size</th></tr>
{''.join(rows)}</table>
<div style="margin-top:24px;color:#64748b;font-size:12px">🛡️ Protected by jarsWAF</div>
</body></html>"""

    def send_json(self, data):
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    def send_binary(self, data):
        self.send_response(200); self.send_header('Content-Type','application/octet-stream'); self.end_headers()
        self.wfile.write(data)
    def send_html(self, html):
        self.send_response(200); self.send_header('Content-Type','text/html'); self.end_headers()
        self.wfile.write(html.encode())
    def log_message(self, fmt, *a): pass

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv)>1 else 9001
    os.makedirs(ROOT, exist_ok=True)
    # Create test files
    with open(os.path.join(ROOT,'README.md'),'w') as f: f.write("# jarsWAF Test\n\nThis file manager is behind jarsWAF.\n")
    with open(os.path.join(ROOT,'config.json'),'w') as f: f.write('{"version":"1.0","debug":false}')
    os.makedirs(os.path.join(ROOT,'documents'), exist_ok=True)
    with open(os.path.join(ROOT,'documents','note.txt'),'w') as f: f.write('Test document content')
    HTTPServer(('0.0.0.0',port), FMHandler).serve_forever()
