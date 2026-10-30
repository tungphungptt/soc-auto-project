import argparse
import os
from .server import make_app, make_server


def main():
    parser = argparse.ArgumentParser(description="SOC mock services (Python standard library only)")
    parser.add_argument("service", choices=["ai", "firewall", "automation"])
    parser.add_argument("--host", default=os.environ.get("SOC_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    port = args.port or {"ai": 8001, "firewall": 8002, "automation": 8000}[args.service]
    app = make_app(args.service)
    server = make_server(args.service, app, args.host, port)
    print(f"{args.service}: http://{args.host}:{port} (mock only)", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if hasattr(app, "conn"):
            app.conn.close()


if __name__ == "__main__":
    main()
