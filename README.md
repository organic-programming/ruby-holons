---
# Cartouche v1
title: "ruby-holons — Ruby SDK for Organic Programming"
author:
  name: "B. ALTER"
created: 2026-02-12
revised: 2026-02-13
access:
  humans: true
  agents: false
status: draft
---
# ruby-holons

**Ruby SDK for Organic Programming** — transport, serve, identity,
and Holon-RPC client utilities for building holons in Ruby.

## Test

```bash
ruby test/holons_test.rb
```

## API surface

| Module | Description |
|--------|-------------|
| `Holons::Transport` | `parse_uri(uri)`, `listen(uri)`, `accept(listener)`, `mem_dial(listener)`, `conn_read(conn)`, `conn_write(conn)`, `close_connection(conn)`, `scheme(uri)` |
| `Holons::Serve` | `parse_flags(args)` |
| `Holons::Identity` | `parse_holon(path)` |
| `Holons::HolonRPCClient` | `connect(url)`, `invoke(method, params)`, `register(method, &handler)`, `close` |

## Transport support

| Scheme | Support |
|--------|---------|
| `tcp://<host>:<port>` | Bound socket (`Listener::Tcp`) |
| `unix://<path>` | Bound UNIX socket (`Listener::Unix`) |
| `stdio://` | Native runtime accept (single-connection semantics) |
| `mem://` | Native runtime in-process pair (`mem_dial` + `accept`) |
| `ws://<host>:<port>` | Listener metadata (`Listener::WS`) |
| `wss://<host>:<port>` | Listener metadata (`Listener::WS`) |

## Parity Notes vs Go Reference

Implemented parity:

- URI parsing and listener dispatch semantics
- Runtime accept path for `tcp`, `unix`, `stdio`, and `mem`
- In-process `mem://` transport with explicit client/server endpoints
- Holon-RPC client protocol support over `ws://` / `wss://` (JSON-RPC 2.0, heartbeat, reconnect)
- Standard serve flag parsing
- HOLON identity parsing

Not yet achievable in this minimal Ruby core (justified gaps):

- `ws://` / `wss://` runtime listener parity:
  - Exposed as metadata only.
  - Full Go-style WebSocket listener parity requires additional HTTP/WebSocket gRPC runtime integration not included here.
- Full gRPC transport parity (`Dial("tcp://...")`, `Dial("stdio://...")`, `Listen("stdio://...")`, and `Serve.Run()` wiring):
  - Not yet provided; requires a dedicated Ruby gRPC adapter layer and stdio transport integration.
