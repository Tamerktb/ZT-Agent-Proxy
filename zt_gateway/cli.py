"""
ZT Gateway CLI — entry point for both smol and production modes.

Usage:
    zt-gateway                         # smol mode (default), port 8000
    zt-gateway --mode smol --port 8080
    zt-gateway --mode prod             # docker-compose up
    zt-gateway --mode prod --down      # docker-compose down
    zt-gateway --mode demo             # register + run test flow
"""
import os
import sys
import argparse
import logging
import subprocess

logger = logging.getLogger(__name__)

DESCRIPTION = "Zero Trust Agentic AI Gateway — security enforcement for AI agents."


def find_repo_root():
    path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(path, "docker-compose.yml")):
        return path
    return os.getcwd()


def cmd_prod(args):
    root = find_repo_root()
    compose_file = os.path.join(root, "docker-compose.prod.yml")
    if not os.path.exists(compose_file):
        compose_file = os.path.join(root, "docker-compose.yml")
    action = "down" if args.down else "up -d" if args.detach else "up"
    cmd = f"docker compose -f \"{compose_file}\" {action}"
    print(f"[prod] {cmd}")
    return subprocess.call(cmd, shell=True)


def cmd_demo(args):
    from zt_gateway.smol_app import SmolSettings, run_smol
    settings = SmolSettings(port=args.port or 8000, log_level="INFO")
    run_smol(settings)


def cmd_smol(args):
    from zt_gateway.smol_app import SmolSettings, run_smol
    settings = SmolSettings(
        host=args.host or "127.0.0.1",
        port=args.port or 8000,
        jwt_secret=args.jwt_secret or "",
        data_dir=args.data_dir or "",
        log_level=args.log_level or "INFO",
        log_format=args.log_format or "text",
    )
    run_smol(settings)


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--mode", choices=["smol", "prod", "demo"], default="smol",
                        help="smol=single-process (default), prod=docker-compose, demo=smol+quick test")
    parser.add_argument("--host", default="127.0.0.1", help="listen host (smol mode)")
    parser.add_argument("--port", type=int, default=8000, help="listen port (smol mode)")
    parser.add_argument("--jwt-secret", help="JWT signing secret (default: auto-generated)")
    parser.add_argument("--data-dir", help="data directory for SQLite databases")
    parser.add_argument("--log-level", default="INFO", help="log level")
    parser.add_argument("--log-format", choices=["text", "json"], default="text", help="log format")
    parser.add_argument("--down", action="store_true", help="docker-compose down (prod mode)")
    parser.add_argument("--detach", "-d", action="store_true", help="docker-compose up -d (prod mode)")

    args = parser.parse_args()

    if args.mode == "prod":
        sys.exit(cmd_prod(args))
    elif args.mode == "demo":
        sys.exit(cmd_demo(args))
    else:
        sys.exit(cmd_smol(args))


if __name__ == "__main__":
    main()
