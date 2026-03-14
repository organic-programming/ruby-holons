# ruby-holons

Ruby SDK for Organic Programming.

It now includes the core daemon-facing lifecycle:
- transport parsing
- `serve` flag parsing and gRPC server runner
- `HolonMeta.Describe` auto-registration from local `protos/` + `holon.yaml`
- discovery and slug-based `connect()`

## Test

```bash
arch -x86_64 bundle install --path vendor/bundle
arch -x86_64 bundle exec ruby -Ilib -e 'Dir["test/**/*_test.rb"].sort.each { |file| load File.expand_path(file) }'
```

On this Apple Silicon workspace, the practical Ruby gRPC path is the
prebuilt `x86_64-darwin` gem under Rosetta.

## API surface

| Module | Description |
|--------|-------------|
| `Holons::Transport` | `parse_uri(uri)`, `listen(uri)`, `accept(listener)`, `mem_dial(listener)`, `conn_read(conn)`, `conn_write(conn)`, `close_connection(conn)`, `scheme(uri)` |
| `Holons::Serve` | `parse_flags(args)`, `run(listen_uri, register)`, `run_with_options(listen_uri, register, reflect = true, on_listen: nil)` |
| `Holons::Identity` | `parse_holon(path)` |
| `Holons::Discover` | `discover(root)`, `discover_local`, `discover_all`, `find_by_slug(slug)`, `find_by_uuid(prefix)` |
| `Holons::Describe` | `build_response(...)`, `service(...)`, `register(server, proto_dir:, holon_yaml_path:)` |
| `Holons` | `connect(target, opts = nil)`, `disconnect(channel)` |
| `Holons::HolonRPCClient` | `connect(url)`, `invoke(method, params)`, `register(method, &handler)`, `close` |

## Current scope

- gRPC server transports: `tcp://`, `unix://`, `stdio://`
- runtime transport helpers: `tcp://`, `unix://`, `stdio://`, `mem://`
- discovery scans local, `$OPBIN`, and cache roots

## Remaining gap vs Go

- No Ruby server reflection support is wired today, so `reflect = true`
  currently degrades to metadata-only serving rather than full gRPC
  reflection.
- No Holon-RPC server module yet.
