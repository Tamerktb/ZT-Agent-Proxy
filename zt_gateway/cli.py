"""
ZT Agent Proxy — transparent HTTP forward proxy for AI agents.

Usage:
    zt-gateway                        # runs the proxy on port 8000, mgmt on 8080
    zt-gateway --proxy-port 8000 --mgmt-port 8080
    zt-gateway --rate-limit 120
"""
import os
import sys
import argparse
import logging


def main():
    parser = argparse.ArgumentParser(
        description="ZT Agent Proxy — transparent HTTP proxy for AI agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zt-gateway
  zt-gateway --proxy-port 8000 --mgmt-port 8080
  HTTP_PROXY=http://localhost:8000 zt-gateway

Set HTTP_PROXY=http://localhost:8000 in your agent's environment to route
all API calls through the proxy for inspection, rate-limiting, and audit.
        """,
    )
    parser.add_argument("--proxy-port", type=int, default=int(os.environ.get("ZT_PROXY_PORT", "8000")),
                        help="Proxy listen port (set HTTP_PROXY to this)")
    parser.add_argument("--mgmt-port", type=int, default=int(os.environ.get("ZT_MGMT_PORT", "8080")),
                        help="Management API port (/stats, /audit/chain)")
    parser.add_argument("--proxy-host", default=os.environ.get("ZT_PROXY_HOST", "127.0.0.1"),
                        help="Proxy listen address")
    parser.add_argument("--rate-limit", type=int, default=int(os.environ.get("ZT_RATE_LIMIT", "60")),
                        help="Max requests per minute per host")
    parser.add_argument("--data-dir", default=os.environ.get("ZT_DATA_DIR", ""),
                        help="Data directory for audit database")
    parser.add_argument("--log-level", default=os.environ.get("ZT_LOG_LEVEL", "INFO"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = parser.parse_args()

    os.environ["ZT_PROXY_PORT"] = str(args.proxy_port)
    os.environ["ZT_MGMT_PORT"] = str(args.mgmt_port)
    os.environ["ZT_PROXY_HOST"] = args.proxy_host
    os.environ["ZT_RATE_LIMIT"] = str(args.rate_limit)
    os.environ["ZT_LOG_LEVEL"] = args.log_level
    if args.data_dir:
        os.environ["ZT_DATA_DIR"] = args.data_dir

    from zt_gateway.smol_app import run
    run()


if __name__ == "__main__":
    main()
