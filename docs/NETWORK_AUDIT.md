# AirDC-I2P Network Audit

## Status

This is the pre-implementation audit. The inherited codebase can create
clearnet sockets and is not yet an I2P-only application. Every item marked
`BLOCK` below must be enforced in code before an I2P release is made.

## Final Allow List

| Operation | Final policy |
| --- | --- |
| SAM control and stream sockets | Allow only a configured loopback numeric address, default `127.0.0.1:7656`. |
| Local Web UI and management API | Allow loopback only by default. |
| I2P hub and peer destinations | Allow only through an established SAM session. |
| Normal IPv4 and IPv6 TCP for DC | Block. |
| Normal UDP for DC | Block. |
| Ordinary DNS lookup for a DC target | Block. |
| SOCKS proxy fallback | Block for DC traffic. |
| UPnP, NAT-PMP, PCP, STUN, external IP discovery | Block and remove from I2P configuration. |
| Clearnet hub lists, update checks, and HTTP metadata | Block by default until explicitly implemented through I2P. |

## Inherited Call Sites Requiring Control

| Location | Capability | Required action |
| --- | --- | --- |
| `connection/socket/Socket.cpp` | `getaddrinfo`, TCP/UDP socket creation, bind, connect, listen, accept, `writeTo` | Put DC callers behind an I2P-only transport factory. Guard direct methods so an I2P build fails closed before resolving or connecting. |
| `connection/socket/BufferedSocket.cpp` | Constructs TCP and TLS socket implementations directly | Make construction transport-aware. Do not let I2P hub or transfer callers instantiate a legacy socket. |
| `connection/UDPServer.cpp` | UDP listening and reads | Do not start it in I2P mode. |
| `search/SearchManager.cpp` | UDP ADC and NMDC search results | Route safe searches through the hub or disable the feature. |
| `hub/AdcHub.cpp` | CTM, RCM, NAT, RNT, address and UDP INF fields | Accept only the I2P transfer capability; omit and reject IP-oriented negotiation. |
| `connectivity/MappingManager.cpp` | MiniUPnPc, NAT-PMP and Windows UPnP mapping | Exclude from I2P target and never initialize it. |
| `connection/http/*` and update code | HTTP transport | Audit individual callers. Do not use it for a hub, transfer, or automatic external service in I2P mode. |
| `airdcpp-webapi/*` | HTTP/WebSocket management listener | Ensure default bind remains loopback and does not share DC listener code. |

## Required Negative Tests

The test suite must prove that these inputs do not cause DNS or non-loopback
network activity:

* `adc://1.1.1.1:411`
* `adc://[2606:4700:4700::1111]:411`
* `adc://192.168.1.10:411`
* `adc://example.com:411`
* an ordinary CTM, RCM, NAT or RNT received from a peer
* an unavailable or malformed SAM bridge

Each failure must contain a usable local error and must not trigger a legacy
TCP, UDP, SOCKS, or DNS fallback.
