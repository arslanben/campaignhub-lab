FROM python:3.12-alpine
WORKDIR /site
# context = repo root; PoC is not duplicated in this folder
COPY attacker/index.html ./index.html
COPY solve/solution_poc.html ./solution_poc.html
CMD ["python", "-c", "import http.server,socketserver; socketserver.TCPServer(('0.0.0.0',8000), http.server.SimpleHTTPRequestHandler).serve_forever()"]
