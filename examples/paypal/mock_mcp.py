#!/usr/bin/env python3
import json, sys
from pathlib import Path

INVOICES = Path(__file__).parent / "invoices"

def reply(req, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": req.get("id")}
    if error:
        out["error"] = error
    else:
        out["result"] = result
    print(json.dumps(out), flush=True)

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        method = req.get("method")
        if method == "initialize":
            reply(req, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "paypal-mock", "version": "0"}})
            continue
        if method == "notifications/initialized":
            continue
        if method == "tools/list":
            reply(req, {"tools": [
                {"name": "read_file", "description": "Read invoice", "inputSchema": {"type": "object"}},
                {"name": "create_order", "description": "Create order", "inputSchema": {"type": "object"}},
                {"name": "pay_order", "description": "Pay order", "inputSchema": {"type": "object"}},
                {"name": "get_order", "description": "Get order", "inputSchema": {"type": "object"}},
            ]})
            continue
        if method != "tools/call":
            reply(req, error={"code": -32601, "message": method})
            continue
        tool = req.get("params", {}).get("name")
        args = req.get("params", {}).get("arguments") or {}
        if tool == "read_file":
            path = INVOICES / Path(args.get("path", "invoice_clean.md")).name
            reply(req, {"content": [{"type": "text", "text": path.read_text()}]})
        elif tool == "create_order":
            reply(req, {"id": "ORDER-99", "status": "CREATED"})
        elif tool == "pay_order":
            reply(req, {"id": args.get("order_id"), "status": "COMPLETED"})
        elif tool == "get_order":
            reply(req, {"id": args.get("order_id"), "status": "CREATED"})
        else:
            reply(req, error={"code": -32601, "message": tool})

if __name__ == "__main__":
    main()