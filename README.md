# Astrolune Connect

Local client for accessing `.lune` domains on the Astrolune network.

## Features

- **Local DNS** — Resolves `.lune` domains via UDP:5335
- **SOCKS5 Proxy** — HTTP CONNECT tunneling for browser access
- **VPN Mode** — Full traffic routing through TUN interface (coming soon)

## Usage

```bash
# Start the local resolver and proxy
astrolune-connect --dns --proxy

# DNS only
astrolune-connect --dns

# Proxy only (forward to existing resolver)
astrolune-connect --proxy --resolver 127.0.0.1:5335
```

## Build

```bash
cmake --preset dev
cmake --build --preset dev
```

## License

MIT
