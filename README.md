# Icicle Relay & Broker

Icicle is a high-performance signalling broker and relay service. It establishes direct WebRTC connections first, uses restricted TURN over UDP when necessary, and falls back to an authenticated HTTPS WebSocket relay when UDP connectivity fails.

- **Direct WebRTC First**: Peer-to-peer connections are prioritized for minimum latency.
- **Restricted UDP TURN**: Allocation traffic stays isolated between authenticated lobby pairs on loopback—no arbitrary forwarding or NAT hairpinning required.
- **HTTPS WebSocket Fallback**: Seamless fallback for restrictive NATs or symmetric firewalls without requiring standard TURN over TLS or client certificate bypasses.

---

## Table of Contents

1. [Building from Source](#building-from-source)
   - [Prerequisites](#prerequisites)
   - [Local Build](#local-build)
   - [Cross-Compiling for Linux from Any Host](#cross-compiling-for-linux-from-any-host)
   - [Building with Docker](#building-with-docker)
2. [Linux Server Installation & Setup](#linux-server-installation--setup)
   - [Step 1: System User and Directory Layout](#step-1-system-user-and-directory-layout)
   - [Step 2: Configuration (`config.json`)](#step-2-configuration-configjson)
   - [Step 3: Authority Signing Key](#step-3-authority-signing-key)
   - [Step 4: Systemd Service Setup](#step-4-systemd-service-setup)
   - [Step 5: Firewall Configuration](#step-5-firewall-configuration)
3. [Reverse Proxy Configuration](#reverse-proxy-configuration)
   - [Caddy (Same Host)](#caddy-same-host)
   - [Nginx (Same Host)](#nginx-same-host)
   - [Proxy on Another Host / Container](#proxy-on-another-host--container)
4. [Optional TURN and Shared Limits](#optional-turn-and-shared-limits)
5. [Authorization and Route Selection](#authorization-and-route-selection)
6. [Abuse Limits](#abuse-limits)
7. [Client Warning](#client-warning)
8. [Validation & Testing](#validation--testing)

---

## Building from Source

Icicle has zero CGO dependencies and can be compiled natively or cross-compiled for Linux from any operating system (macOS, Linux, Windows, BSD).

### Prerequisites

- [Go](https://go.dev/dl/) **1.24** or newer installed on your build machine (or Docker).

### Compiling for your current host

To build an executable for your current OS and architecture:

```bash
# Clone the repository
git clone https://github.com/roblox-in-a-box/icicle.git
cd icicle

# Compile stripped release binary
go build -ldflags="-s -w" -o icicle ./cmd/icicle
```

### Cross-Compiling for Linux from Any Host

You can compile a static Linux binary on macOS or Windows without installing a cross-compiler toolchain:

**Compiling from macOS / Linux:**

Compiling for `AMD64` Linux:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o icicle-linux-amd64 ./cmd/icicle
```

Compiling for `ARM64` Linux:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o icicle-linux-arm64 ./cmd/icicle
```

**Compiling from Windows:**

Open PowerShell terminal

Compiling for `AMD64` Linux:

```powershell
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o icicle-linux-amd64 ./cmd/icicle
```

Compiling for `ARM64` Linux:

```powershell
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="arm64"; go build -trimpath -ldflags="-s -w" -o icicle-linux-arm64 ./cmd/icicle
```

### Building with Docker

If you do not have Go 1.24+ installed on your workstation, build inside the official Go container:

Build for `AMD64` Linux:
```bash
docker run --rm -v "$PWD":/src -w /src golang:1.24-alpine \
    sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o icicle-linux-amd64 ./cmd/icicle"
```

Build for `ARM64` Linux:
```bash
docker run --rm -v "$PWD":/src -w /src golang:1.24-alpine \
    sh -c "CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o icicle-linux-arm64 ./cmd/icicle"
```

---

## Linux Server Installation & Setup

Follow these steps to deploy Icicle as a hardened, unprivileged system service on your Linux server (Debian, Ubuntu, Fedora, RHEL, Rocky Linux, Arch).

### Step 1: System User and Directory Layout

1. Transfer your compiled binary to the server:

   ```bash
   scp icicle-linux-amd64 user@your-server-ip:/tmp/icicle
   ```

   or download latest release from GitHub (coming soon)

2. SSH into your server and create a dedicated system user and group:

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin icicle
   ```

3. Install the binary to `/usr/local/bin`:

   ```bash
   sudo mv /tmp/icicle /usr/local/bin/icicle
   sudo chown root:root /usr/local/bin/icicle
   sudo chmod 755 /usr/local/bin/icicle
   ```

4. Create configuration and state directories:

   ```bash
   # Configuration directory
   sudo mkdir -p /etc/icicle
   sudo chmod 755 /etc/icicle

   # State directory (for authority key)
   sudo mkdir -p /var/lib/icicle
   sudo chown icicle:icicle /var/lib/icicle
   sudo chmod 700 /var/lib/icicle
   ```

### Step 2: Configuration (`config.json`)

Create `/etc/icicle/config.json`:

```bash
sudo nano /etc/icicle/config.json
```

Populate it according to your deployment model:

#### Basic Setup (HTTPS WebSocket Fallback only, no UDP TURN)

```json
{
  "Admins": {},
  "TrustLoopbackProxy": true
}
```

#### Full Setup (with UDP TURN enabled)

```json
{
  "Admins": {},
  "TrustLoopbackProxy": true,
  "TURN": {
    "PublicIP": "203.0.113.10",
    "UDPListen": "0.0.0.0:3478",
    "URLs": ["turn:turn.example.com:3478?transport=udp"],
    "BytesPerSecond": 524288,
    "TotalBytesPerSecond": 8388608,
    "MaxPairs": 128
  }
}
```

Set appropriate file permissions:

```bash
sudo chown root:icicle /etc/icicle/config.json
sudo chmod 640 /etc/icicle/config.json
```

### Step 3: Authority Signing Key

Icicle uses an Ed25519 signing key (`icicle-authority.key`) to issue admission tickets and authorize connections.

- **Automatic Generation**: When Icicle starts with `-authority-key /var/lib/icicle/icicle-authority.key`, it automatically generates a 32-byte Ed25519 seed if the file does not already exist.
- **State Directory Permissions**: Because the service runs as the unprivileged `icicle` user, ensure `/var/lib/icicle` is writable by `icicle:icicle` (as configured in Step 1).
- **Backups**: Back up `/var/lib/icicle/icicle-authority.key` so the server preserves its issuer identity across server rebuilds or migrations.

### Step 4: Systemd Service Setup

Create `/etc/systemd/system/icicle.service`:

```bash
sudo nano /etc/systemd/system/icicle.service
```

Paste the following unit configuration:

```ini
[Unit]
Description=Icicle Relay & Broker Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=icicle
Group=icicle
WorkingDirectory=/var/lib/icicle

ExecStart=/usr/local/bin/icicle \
    -config /etc/icicle/config.json \
    -authority-key /var/lib/icicle/icicle-authority.key \
    -listen 127.0.0.1:8080

Restart=always
RestartSec=5s

# Resource limits
LimitNOFILE=65535

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/icicle
StateDirectory=icicle

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
# Reload systemd manager configuration
sudo systemctl daemon-reload

# Enable service on boot and start immediately
sudo systemctl enable --now icicle

# Verify status
sudo systemctl status icicle

# Follow live logs
sudo journalctl -u icicle -f
```

### Step 5: Firewall Configuration

Open the required public ports on your host firewall:

#### Using UFW (Ubuntu / Debian)

```bash
# Allow HTTP/HTTPS for reverse proxy
sudo ufw allow 80/tcp comment 'HTTP ACME challenge'
sudo ufw allow 443/tcp comment 'HTTPS Icicle broker & relay'

# Allow UDP TURN (if enabled in config.json)
sudo ufw allow 3478/udp comment 'Icicle UDP TURN'

sudo ufw reload
```

#### Using firewalld (RHEL / Rocky / Fedora)

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https

# Allow UDP TURN (if enabled in config.json)
sudo firewall-cmd --permanent --add-port=3478/udp

sudo firewall-cmd --reload
```

---

## Reverse Proxy Configuration

A reverse proxy terminates public TLS on port `443` and handles WebSocket connection upgrades before proxying loopback traffic to Icicle on port `8080`.

Configure clients to connect to your domain:
`wss://icicle.example.com`

### Caddy (Same Host)

Caddy handles automatic SSL/TLS certificate provisioning and renewals via Let's Encrypt / ZeroSSL.

Create or update `/etc/caddy/Caddyfile`:

```caddyfile
icicle.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Icicle-Client-IP {http.request.remote.host}
    }
}
```

Reload Caddy:

```bash
sudo systemctl reload caddy
```

### Nginx (Same Host)

If using Nginx, configure a virtual host with TLS and WebSocket proxy headers:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name icicle.example.com;
    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name icicle.example.com;

    ssl_certificate     /etc/letsencrypt/live/icicle.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/icicle.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        proxy_set_header CF-Connecting-IP $remote_addr;

        proxy_set_header Forwarded "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Pass true client IP to Icicle
        proxy_set_header X-Icicle-Client-IP $remote_addr;

        # Keep relay WebSocket connections alive
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_buffering off;
    }
}
```

Reload Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Proxy on Another Host / Container

When Nginx, Caddy, or an ingress proxy runs on a separate machine or container, list its IP address or subnet in `TrustedProxies` instead of using `TrustLoopbackProxy`:

```json
{
  "Admins": {},
  "TrustedProxies": ["10.0.0.5", "172.18.0.0/16"]
}
```

- Entries can be single IPv4/IPv6 addresses or CIDR blocks (e.g. `10.0.0.0/24`). Wildcards trusting all addresses are rejected.
- Configure Icicle to bind to a reachable network interface (e.g., `-listen 0.0.0.0:8080`), and firewall port `8080` so only the proxy host can reach it.
- **Behind Cloudflare**: When proxying through Cloudflare, configure Nginx to restore the real visitor address via `real_ip_header CF-Connecting-IP` and `set_real_ip_from` with Cloudflare's published IP ranges, ensuring `$remote_addr` reflects the player rather than Cloudflare edge servers.

---

## Optional TURN and Shared Limits

Add a `TURN` section to `/etc/icicle/config.json` to enable UDP TURN:

```json
{
  "Admins": {},
  "TrustLoopbackProxy": true,
  "TURN": {
    "PublicIP": "203.0.113.10",
    "UDPListen": "0.0.0.0:3478",
    "URLs": ["turn:turn.example.com:3478?transport=udp"],
    "BytesPerSecond": 524288,
    "TotalBytesPerSecond": 8388608,
    "MaxPairs": 128
  }
}
```

- Replace `PublicIP` and `URLs` with your server's public IPv4 address and DNS name.
- The UDP listener must be reachable directly by clients and is **not** proxied through Caddy or Nginx.
- Omitting `PublicIP`, `UDPListen`, and `URLs` retains the shared quotas for HTTPS fallback without binding the UDP TURN socket.
- Without a `TURN` section, the default rate and pair quotas apply to HTTPS fallback.

---

## Authorization and Route Selection

1. The client signs a preparation request identifying its lobby, username, identity, and build.
2. The registered host must approve the request before Icicle issues a pair grant.
3. The host and client receive distinct, randomized TURN credentials.
4. The subsequent signed offer must preserve the approved identity and build exactly.
5. Signed join tickets authorize gameplay across both relay paths:
   - WebRTC connections verify their DTLS fingerprints.
   - HTTPS fallback relies on authenticated broker connections and approved session pairing.
6. The broker terminates HTTPS relay transport through the reverse proxy, so relay operators can observe gameplay payloads on that path.

### Routing Mechanics & Isolation

- **ICE Route Preference**: ICE attempts a direct peer-to-peer route first. If unavailable, it selects the approved UDP TURN route.
- **Automatic HTTPS Fallback**: If ICE fails or has not connected within eight seconds after receiving the signed answer, peers fall back to the authenticated HTTPS relay.
- **Lobby Affinity**: Once a host uses a relay, subsequent client joins prefer that relay path for the active lobby. A host on HTTPS fallback causes later joins to use HTTPS fallback as well.
- **Packet Isolation**: TURN validates destination addresses and ports on every packet. Traffic only flows between live allocations belonging to opposite sides of the same approved pair.
- **No Arbitrary Routing**: All allocation traffic is translated to loopback inside the server. There is no general internet egress, private network probing, arbitrary TCP dialing, or cross-lobby forwarding.
- **Grant Expiration**: Grants expire after two minutes unless renewed while both members remain registered. Disconnecting either party, rejecting admission, revoking the game peer, or closing the host immediately revokes the grant and closes relay sockets.

---

## Abuse Limits

Traffic limits permit short bursts (up to one second) and drop forwarded packets under sustained congestion so RakNet can handle retransmission:

| Resource                                | Default Limit                 | Description / Behavior                     |
| :-------------------------------------- | :---------------------------- | :----------------------------------------- |
| **Approved pair grants**                | `128`                         | Concurrent session pairs on the broker     |
| **Grants per host**                     | `16`                          | Maximum active pairs per host              |
| **Grants per client/host source IP**    | `32`                          | Maximum pairs allocated to a single IP     |
| **TURN allocations per credential**     | `4`                           | Relayed port allocations per side          |
| **Payload per credential (both paths)** | `512 KiB/s`                   | Forwarding budget per pair                 |
| **Payload packets per credential**      | `2000/s`                      | Packet throughput per pair                 |
| **Aggregate relay payload**             | `8 MiB/s`                     | Total server forwarding throughput         |
| **UDP listener packet processing**      | `20000/s`                     | Global UDP ingestion limit                 |
| **UDP control requests**                | `200/s` global, `40/s` per IP | STUN/TURN binding & allocation requests    |
| **UDP control source tracking**         | `4096` entries                | Active tracking table size                 |
| **Broker WebSockets**                   | `1024` global, `64` per IP    | Concurrent client WebSocket sessions       |
| **Registered clients per lobby**        | `64`                          | Client registrations per lobby             |
| **HTTPS relay packet size**             | `1464` bytes                  | Maximum packet size before framing         |
| **HTTPS relay frame size**              | `2048` bytes                  | Maximum frame size including wire metadata |
| **Queued HTTPS relay bytes/packets**    | `128 KiB` / `128` packets     | Per-recipient backlog before dropping      |
| **HTTPS client input limit**            | `2000` pkt/s, `1 MiB/s`       | Exceeding closes client connection         |
| **HTTPS host input limit**              | `20000` pkt/s, `16 MiB/s`     | Exceeding closes host connection           |

- TURN payload is accounted on both send and receive paths; HTTPS relay payload is charged once per forwarded packet.
- The UDP listener suppresses public STUN binding discovery responses.
- UDP TURN library packet logging is disabled to prevent disk filling and log amplification.

---

## Client Warning

When an indirect relay path is selected, the desktop client pauses gameplay admission and displays:

```
DEGRADED PERFORMANCE

Your network could not establish a direct connection. Try enabling UPnP on your router, or continue with increased ping.
```

- **OK**: Accepts relay routing and saves `RelayWarningAcknowledged` to local settings.
- **GO BACK**: Cancels the connection attempt without suppressing future warnings.

---

## Validation & Testing

### Broker & Relay Test Suite

Run unit and race-condition tests across all packages:

```bash
go test -race ./...
```

The test suite exercises:

- Live UDP TURN allocation and relay traffic.
- Paired destination isolation and blocked peer reflection.
- Expiration, admission revocation, and allocation quota enforcement.
- Bandwidth throttling and HTTPS relay queue isolation.

### Engine Transport Tests

The game engine's `IcicleTransportTests` can be pointed at your running broker:

```bash
# Require UDP TURN
./engine_tests --broker-url wss://icicle.example.com --relay

# Force the first connection to use the HTTPS relay
./engine_tests --broker-url wss://icicle.example.com --websocket

# Test automatic fallback after simulated UDP failure
./engine_tests --broker-url wss://icicle.example.com --fallback
```
