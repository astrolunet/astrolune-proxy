# Astrolune Proxy

Proxy and gateway for accessing `.lune` sites on the Astrolune network.

## Components

### SOCKS5 Proxy
SOCKS5/HTTP CONNECT proxy that tunnels browser traffic through the Astrolune network.

### Proxy Connector
Reverse tunnel connector for self-hosted servers to expose services on `.lune` domains.

### Lune Gateway
HTTP gateway that serves static `.lune` sites from the content-addressed storage.

### Connect Client
CLI orchestrator that manages DNS resolution and proxy connections.

## Usage

```bash
# Start proxy + DNS
astrolune-connect --dns --proxy

# Expose a local server on .lune
proxy-connector --local-port 3000 --name myapp.lune
```

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## License

MIT
