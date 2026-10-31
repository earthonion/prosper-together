#!/usr/bin/env python3
"""HTTP logger and Lua REPL server for Prosper Together."""

import argparse
import http.server
import os
import threading
import time
import urllib.parse
from datetime import datetime


class LuaREPL:
    def __init__(self):
        self.pending_code = None
        self.lock = threading.Lock()

    def queue(self, code):
        with self.lock:
            self.pending_code = code

    def take(self):
        with self.lock:
            code = self.pending_code
            self.pending_code = None
            return code


repl = LuaREPL()


class LogHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parts = self.path.split('/', 2)
        cmd = parts[1] if len(parts) > 1 else ''
        data = urllib.parse.unquote(parts[2]) if len(parts) > 2 else ''
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

        if cmd == 'poll':
            time.sleep(0.2)
            code = repl.take()
            if code is None:
                self.send_response(204)
                self.end_headers()
                return
            body = code.encode('utf-8') if isinstance(code, str) else code
            print(f'[{ts}] Sending {len(body)} Lua bytes', flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        print(f'[{ts}] [{cmd}] {data}', flush=True)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, format, *args):
        pass


def create_server(port, queue_path):
    def watch_queue():
        while True:
            try:
                with open(queue_path, 'rb') as f:
                    code = f.read()
                os.unlink(queue_path)
                repl.queue(code)
                print(f'Queued {len(code)} Lua bytes', flush=True)
            except FileNotFoundError:
                pass
            except Exception as e:
                print(f'Queue error: {e}', flush=True)
            time.sleep(0.1)

    threading.Thread(target=watch_queue, daemon=True).start()
    return http.server.ThreadingHTTPServer(('0.0.0.0', port), LogHandler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8099)
    parser.add_argument('--queue', default=os.path.join(os.path.dirname(__file__),
                        'build_dst', 'repl_command.lua'))
    args = parser.parse_args()
    server = create_server(args.port, args.queue)
    print(f'Prosper HTTP log+REPL server on 0.0.0.0:{args.port}', flush=True)
    print(f'Lua queue: {args.queue}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
