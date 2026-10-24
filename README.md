# Icicle relay

Icicle uses direct WebRTC connections first, restricted TURN over UDP when necessary, and an authenticated HTTPS WebSocket relay when UDP connectivity fails
Go 1.24 or newer is required
Deploy the updated engine and broker together because the engine now uses the preparation and relay signalling messages

The WebSocket fallback is available through the broker endpoint by default
Ordinary Caddy or Nginx handles HTTPS certificates and WebSocket upgrades without an extra plugin
No ICE dependency fork or client certificate bypass is required

## Reverse proxy and port forwarding

Use a hostname pointing to your server and configure a reverse proxy such as Caddy or Nginx

### Caddy

```caddyfile
icicle.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Icicle-Client-IP {http.request.remote.host}
    }
}
```

### Nginx

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name icicle.example.com;
    return 308 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name icicle.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://ICICLE_HOST:8080;

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

        proxy_set_header X-Icicle-Client-IP $remote_addr;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_buffering off;
    }
}

```

Run Icicle on its default loopback HTTP listener and configure clients to use `wss://icicle.example.com`
The reverse proxy manages public HTTPS certificates
Set `"TrustLoopbackProxy": true` in the Icicle configuration for loopback proxy deployments
The reverse proxy must overwrite `X-Icicle-Client-IP` as shown rather than forwarding a client-supplied value
Keep the broker port 8080 private
Expose TCP 443 for HTTPS signalling and fallback relay traffic
TCP 80 is also recommended for certificate challenges and HTTP redirects
Do not put a short stream timeout on WebSocket connections

## Reverse proxy on another host

When Nginx, Caddy or another proxy runs on a different machine or container, list its address in `TrustedProxies` instead of using `TrustLoopbackProxy`

```json
{
  "Admins": {},
  "TrustedProxies": ["10.0.0.5"]
}
```

Entries are single IPv4 or IPv6 addresses or CIDR ranges such as `10.0.0.0/24`
Ranges that trust every address are rejected
Listen on an address the proxy can reach, for example `-listen 0.0.0.0:8080`, and firewall port 8080 so only the proxy can connect

Behind Cloudflare's proxy, Nginx must first restore the visitor address with `real_ip_header CF-Connecting-IP` and `set_real_ip_from` for each Cloudflare range so `$remote_addr` is the player rather than Cloudflare
Without a trusted proxy setting, every player appears to come from the proxy and shares one source allowance

Players do not need manual port forwarding to join or host through a relay
TURN over UDP is optional and needs one additional public port, UDP 3478
Forward TCP 443 to the reverse proxy and UDP 3478 to Icicle if the service runs behind a router
A server behind carrier-grade NAT still needs a publicly reachable host or tunnel
A VPS with a public address is recommended for dependable availability and bandwidth

Both sides of each TURN connection use allocations on this Icicle process
Approved allocation traffic stays on loopback inside the server
Only the TURN control listener needs public UDP access
No public relay allocation port range or NAT hairpin support is needed
All allocations for a pair must remain on the same process
Multiple broker or TURN processes require explicit session affinity

UPnP is not required for the relay paths
The engine does not currently request UPnP mappings
Enabling UPnP on a router alone therefore does not guarantee a direct connection

## Optional TURN and shared limits

Add a `TURN` section to the broker configuration to enable UDP TURN

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

Replace the example address and hostname with the actual public IPv4 address and DNS name
The UDP listener must be reachable directly and is not proxied through Caddy or Nginx
Omit `PublicIP`, `UDPListen` and `URLs` to configure the shared quotas for HTTPS fallback without enabling TURN
Without a `TURN` section the same default quotas apply to HTTPS fallback
This implementation intentionally uses UDP TURN and HTTPS WebSockets rather than standard TURN over TLS

## Authorization and route selection

The client signs a preparation request identifying its lobby, username, identity and build
The registered host must approve it before Icicle issues a pair grant
The host and client receive separate random TURN credentials
The subsequent signed offer must preserve the approved identity and build exactly
Signed join tickets authorize gameplay on both relay paths
WebRTC connections additionally verify their DTLS fingerprints
The HTTPS fallback instead relies on the authenticated broker connections and approved session pairing
The broker terminates HTTPS relay transport through the reverse proxy, so relay operators can observe gameplay payloads on that path

ICE prefers a direct route initially and can select an approved UDP TURN route
If ICE fails, or has not connected within eight seconds after the signed answer arrives, the peers request the HTTPS fallback
The fallback cannot start before broker admission
Once a host uses a relay, subsequent joins prefer that relay path for the live lobby
A host using HTTPS fallback causes later joins to use HTTPS fallback as well

TURN checks destination address and port on every packet
Packets can travel only between live allocations belonging to opposite sides of the same approved pair
Allocation traffic is translated to loopback while preserving advertised peer addresses in TURN responses
There is no general internet egress, private network access, arbitrary TCP dialing or cross-lobby forwarding
Direct-to-relay traffic is intentionally blocked
HTTPS relay destinations are resolved from the authenticated lobby membership rather than a caller-supplied IP address
Clients can send only to their host and hosts can send only to their approved clients

Grants expire after two minutes unless renewed while both members remain registered
Disconnecting either member, rejecting admission, revoking the game peer or closing the host revokes its grant
TURN relay sockets close on revocation and HTTPS relay forwarding stops
Credentials and gameplay payloads are not logged

## Abuse limits

Limits permit a one second burst and drop forwarded traffic under sustained congestion
Approved pair grants also reserve capacity for direct connections that might later need a relay

| Resource                                          | Default limit                                       |
| ------------------------------------------------- | --------------------------------------------------- |
| Approved pair grants                              | 128                                                 |
| Approved pair grants per host                     | 16                                                  |
| Approved pair grants per client or host source IP | 32                                                  |
| TURN allocations per credential                   | 4                                                   |
| Payload per credential across both relay paths    | 512 KiB/s                                           |
| Payload packets per credential                    | 2000/s                                              |
| Aggregate relay payload processing                | 8 MiB/s                                             |
| UDP listener packet processing                    | 20000/s                                             |
| UDP control requests                              | 200/s globally and 40/s per source IP               |
| UDP control source tracking                       | 4096 entries                                        |
| Broker WebSockets                                 | 1024 globally and 64 per non-loopback TCP source IP |
| Registered clients per lobby                      | 64                                                  |
| HTTPS relay packet size                           | 1464 bytes                                          |
| HTTPS relay frame size including metadata         | 2048 bytes                                          |
| Queued HTTPS relay bytes per recipient            | 128 KiB                                             |
| Queued HTTPS relay packets per recipient          | 128                                                 |
| HTTPS client input                                | 2000 packets/s and 1 MiB/s                          |
| HTTPS host input                                  | 20000 packets/s and 16 MiB/s                        |

TURN payload is charged on both the send and receive paths
HTTPS relay payload is charged once per forwarded packet
Exceeding the HTTPS input limits closes the sender
Exceeding forwarding budgets drops packets so RakNet can retransmit
Signalling has a separate bounded priority queue and a separate existing request rate limit
A full relay queue drops gameplay packets rather than closing its recipient

The UDP listener does not answer public STUN binding discovery
TURN authentication challenges are still required and are bounded by the UDP control limits
TURN library packet logging is suppressed to prevent log amplification
Existing broker connection and admission logs remain available

Broker source limits use TCP addresses by default
With `TrustLoopbackProxy` enabled, loopback peers can supply the single IP in `X-Icicle-Client-IP`
Peers inside `TrustedProxies` can supply it as well
Headers from public connections cannot override source quotas
Unconfigured proxies share their source allowance rather than bypassing pair limits
Apply connection and request limits at the public proxy as well
A container proxy on a non-loopback address is not trusted by `TrustLoopbackProxy` and needs a `TrustedProxies` entry
Keep the UDP relay allocation ports private and use provider-level DDoS filtering and bandwidth alerts
Application limits cannot stop an upstream attack from filling the network link

## Client warning

When a relay is selected, the desktop client pauses gameplay admission and displays

**DEGRADED PERFORMANCE**

Your network could not establish a direct connection. Try enabling UPnP on your router, or continue with increased ping.

**OK** accepts the relay and permanently saves `RelayWarningAcknowledged` in local settings
**GO BACK** cancels the game connection without suppressing future warnings
The preference is per local installation

## Validation

Run `go test -race ./...` for the broker and relay tests
Tests cover actual UDP TURN traffic, paired destination isolation, expiry, revocation, allocation quotas, bandwidth limits, disabled public binding reflection, HTTPS relay authorization and queue isolation

The engine `IcicleTransportTests` accepts a broker WebSocket URL
Use `--relay` to require UDP TURN, `--websocket` to force the first HTTPS relay connection, or `--fallback` to test automatic HTTPS fallback after failed UDP connectivity
The latter two modes also verify that subsequent clients follow the host's HTTPS relay preference
All relay modes require consent and check the selected transport before testing fragmented RakNet traffic
