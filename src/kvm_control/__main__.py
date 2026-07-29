from __future__ import annotations

import argparse
import os

import uvicorn


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("service", choices=["control-api", "lock-api", "mcp-api"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    parser.add_argument("--control-url")
    parser.add_argument("--lock-url")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--token")
    args = parser.parse_args()

    if args.config:
        os.environ["KVM_CONTROL_CONFIG"] = args.config

    from .service import build_services

    if args.service == "control-api":
        from .control_api import create_app as create_control_app

        app = create_control_app(build_services(args.config))
        port = args.port or 8000
    elif args.service == "lock-api":
        from .lock_api import create_app as create_lock_app

        app = create_lock_app(build_services(args.config))
        port = args.port or 8001
    else:
        from .config import load_config
        from .mcp_api import create_app as create_mcp_app

        config = load_config(args.config) if args.config else None
        username = args.username or os.environ.get("KVM_CONTROL_MCP_USERNAME")
        password = args.password or os.environ.get("KVM_CONTROL_MCP_PASSWORD")
        token = args.token or os.environ.get("KVM_CONTROL_MCP_TOKEN")
        if config and config.auth.enabled:
            username = username or config.auth.username
            password = password or config.auth.password
        app = create_mcp_app(
            control_url=args.control_url or os.environ.get("KVM_CONTROL_MCP_CONTROL_URL", "http://127.0.0.1:8000"),
            lock_url=args.lock_url or os.environ.get("KVM_CONTROL_MCP_LOCK_URL", "http://127.0.0.1:8001"),
            token=token,
            username=username,
            password=password,
        )
        port = args.port or 8002

    uvicorn.run(app, host=args.host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
