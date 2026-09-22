"""Entry point:  python3 -m netdisco [--port 8765] [--no-browser]"""
import argparse
import sys

from .server import serve


def main():
    if sys.version_info < (3, 9):
        sys.exit("Network Discovery needs Python 3.9 or newer.")
    p = argparse.ArgumentParser(prog="netdisco", description="Home network health & device discovery dashboard")
    p.add_argument("--port", type=int, default=8765, help="local port for the dashboard (default 8765)")
    p.add_argument("--no-browser", action="store_true", help="don't open the dashboard automatically")
    p.add_argument("--health-interval", type=float, default=5.0, help="seconds between health checks")
    p.add_argument("--rescan", type=float, default=300.0, help="seconds between automatic device scans (0 = off)")
    p.add_argument("--demo", action="store_true", help="show sample data instead of scanning (for trying the UI)")
    a = p.parse_args()
    serve(port=a.port, open_browser=not a.no_browser, health_interval=a.health_interval,
          rescan_interval=a.rescan, demo=a.demo)


if __name__ == "__main__":
    main()
