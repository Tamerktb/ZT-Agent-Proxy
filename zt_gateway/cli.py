"""
ZT Agent Proxy — transparent HTTP forward proxy for AI agents.

Usage:
    zt-gateway                            # proxy :8000, mgmt :8080
    zt-gateway --rate-limit 120
    zt-gateway --mgmt-token SECRET        # require bearer token on mgmt API
    zt-gateway --block-domain evil.com --allow-domain api.openai.com
    zt-gateway --action injection=warn --action pii=block
"""
import os
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="ZT Agent Proxy — transparent HTTP proxy for AI agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zt-gateway
  zt-gateway --rate-limit 120 --mgmt-token s3cret
  zt-gateway --block-domain tracker.example --action injection=warn
  HTTP_PROXY=http://localhost:8000 <your-agent>

Set HTTP_PROXY=http://localhost:8000 in your agent's environment to route
all API calls through the proxy for inspection, rate-limiting, and audit.
        """,
    )
    parser.add_argument("--proxy-port", type=int, default=int(os.environ.get("ZT_PROXY_PORT", "8000")),
                        help="Proxy listen port (set HTTP_PROXY to this)")
    parser.add_argument("--mgmt-port", type=int, default=int(os.environ.get("ZT_MGMT_PORT", "8080")),
                        help="Management API port (/stats, /audit/chain, /check)")
    parser.add_argument("--proxy-host", default=os.environ.get("ZT_PROXY_HOST", "127.0.0.1"),
                        help="Proxy listen address")
    parser.add_argument("--rate-limit", type=int, default=int(os.environ.get("ZT_RATE_LIMIT", "60")),
                        help="Max requests per minute per host")
    parser.add_argument("--data-dir", default=os.environ.get("ZT_DATA_DIR", ""),
                        help="Data directory for audit database + forensics.jsonl")
    parser.add_argument("--log-level", default=os.environ.get("ZT_LOG_LEVEL", "INFO"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--policy", default=os.environ.get("ZT_POLICY_FILE", ""),
                        help="Path to policy JSON (actions, domains, rate_limit_per_min)")
    parser.add_argument("--mgmt-token", default=os.environ.get("ZT_MGMT_TOKEN", ""),
                        help="Require 'Authorization: Bearer <token>' on management API")
    parser.add_argument("--allow-domain", action="append", default=None, metavar="DOMAIN",
                        help="Allowlist domain (repeatable; non-empty => default deny)")
    parser.add_argument("--block-domain", action="append", default=None, metavar="DOMAIN",
                        help="Blocklist domain (repeatable)")
    parser.add_argument("--action", action="append", default=None, metavar="CATEGORY=ACTION",
                        help="Set action for a category: injection|pii|secret|vuln = block|warn|log")

    args = parser.parse_args()

    os.environ["ZT_PROXY_PORT"] = str(args.proxy_port)
    os.environ["ZT_MGMT_PORT"] = str(args.mgmt_port)
    os.environ["ZT_PROXY_HOST"] = args.proxy_host
    os.environ["ZT_RATE_LIMIT"] = str(args.rate_limit)
    os.environ["ZT_LOG_LEVEL"] = args.log_level
    if args.data_dir:
        os.environ["ZT_DATA_DIR"] = args.data_dir
    if args.policy:
        os.environ["ZT_POLICY_FILE"] = args.policy
    if args.mgmt_token:
        os.environ["ZT_MGMT_TOKEN"] = args.mgmt_token
    if args.allow_domain:
        os.environ["ZT_ALLOW_DOMAINS"] = ",".join(args.allow_domain)
    if args.block_domain:
        os.environ["ZT_BLOCK_DOMAINS"] = ",".join(args.block_domain)
    for spec in args.action or []:
        if "=" not in spec:
            parser.error(f"--action expects CATEGORY=ACTION, got '{spec}'")
        cat, act = spec.split("=", 1)
        if act not in ("block", "warn", "log"):
            parser.error(f"--action action must be block|warn|log, got '{act}'")
        os.environ[f"ZT_ACTION_{cat.upper()}"] = act

    from zt_gateway.smol_app import run
    run()


if __name__ == "__main__":
    main()
