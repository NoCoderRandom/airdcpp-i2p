# AirDC-I2P Architecture Before Transport Changes

This document records the inherited AirDC++ Web Client architecture before
I2P-specific behavior is added. It is an audit record, not a claim that the
current fork is safe for anonymous use.

## Baseline

| Item | Value |
| --- | --- |
| Upstream | `https://github.com/airdcpp-web/airdcpp-webclient` |
| Upstream branch | `master` |
| Recorded commit | `56bf01a929d68e11fca1445e73207995727a50e1` |
| Fork branch | `i2p-main` |
| License | Unchanged upstream GPL licensing and attribution |

The local clone keeps the original project under the `upstream` remote and
uses `origin` for `https://github.com/NoCoderRandom/airdcpp-i2p`.

## Build Baseline

Ubuntu 24.04 with GCC 13.3, CMake 3.28, OpenSSL 3.0, Boost 1.83, LevelDB,
MiniUPnPc, NAT-PMP, TBB, websocketpp and nlohmann-json was used.

* `airdcpp-core` builds successfully as `libairdcpp.so.2.14.0`.
* The complete Web Client configuration succeeds with `INSTALL_WEB_UI=OFF`.
* The complete Web Client build stops in websocketpp 0.8.2 before compiling
  project Web API code. websocketpp uses constructor and destructor template-id
  syntax that is rejected by the C++20 mode required by the upstream CMake
  configuration. The same syntax is present in websocketpp upstream.
* The current tree does not register CTest tests for this target.

The WebSocket++ compatibility issue is tracked as a downstream build task. It
must be fixed reproducibly without lowering the I2P transport security policy
or editing system headers.

## Existing Network Layers

| Area | Key paths | Inherited behavior | I2P disposition |
| --- | --- | --- | --- |
| Raw sockets | `airdcpp-core/airdcpp/connection/socket/Socket.*` | Creates TCP and UDP sockets, resolves names, binds, listens, accepts, and can use SOCKS5. | Replace DC use with an explicit I2P transport. Raw IP operations must be denied in I2P builds. |
| Buffered streams | `connection/socket/BufferedSocket.*` | Constructs `Socket` or `SSLSocket` directly for outgoing and accepted streams. | Add a transport-selected stream factory; I2P streams must be created through SAM only. |
| TLS streams | `connection/socket/SSLSocket.*` | Wraps ordinary TCP sockets with TLS. | Retain only where ADC-over-I2P needs TLS; it must not create a direct TCP path. |
| Hub sessions | `hub/Client.*`, `hub/AdcHub.*`, `hub/NmdcHub.*` | Connects to hubs and handles ADC CTM, RCM, NAT and RNT. | Allow `adc+i2p` hubs only. Disable NMDC and direct IP transfer negotiation. |
| Peer transfers | `connection/ConnectionManager.*`, `connection/UserConnection.*`, `transfer/*` | Uses direct client sockets and active/passive negotiation. | Replace with SAM `STREAM CONNECT` and `STREAM ACCEPT`. |
| UDP search | `connection/UDPServer.*`, `search/SearchManager.*` | Opens UDP listeners and sends ADC/NMDC UDP search and results. | Disable; use hub-routed ADC search only. |
| Connectivity mapping | `connectivity/MappingManager.*`, `connectivity/mappers/*` | Uses UPnP and NAT-PMP to discover or map public ports. | Remove from the I2P build and configuration surface. |
| Address advertisement | `hub/AdcHub.cpp` INF handling | Emits or consumes `I4`, `I6`, `U4`, `U6`, TCP and NAT features. | Omit address and UDP fields; advertise only a documented I2P capability. |
| HTTP helpers | `connection/http/*`, update and hub-list code | Can make ordinary HTTP connections for non-DC features. | Audit separately. I2P mode must not fetch hub lists or update metadata through clearnet. |
| Local Web API | `airdcpp-webapi/*`, `airdcppd/*` | Hosts the Web UI and API. | Bind management endpoints to loopback by default; this is distinct from DC transport. |

## Intended Transport Boundary

The I2P edition will introduce an isolated transport layer under
`airdcpp-core/airdcpp/i2p/` and `airdcpp-core/airdcpp/transport/`.

1. A long-lived SAM 3.1 stream session owns the persistent I2P destination.
2. New outbound hub and peer connections obtain a SAM virtual stream.
3. Incoming peer streams are accepted from that same SAM session.
4. Legacy socket construction remains available only for explicitly local
   management operations during the migration. DC code must not be able to
   select it.
5. Network policy checks occur before any DNS lookup or IPv4/IPv6 socket
   creation, not only in the user interface.

SAM design follows the stable cross-router subset documented by the I2P
project: [SAM v3](https://www.i2p.net/en/docs/api/samv3/). ADC capability and
command decisions will follow the [ADC base protocol](https://adc.sourceforge.io/ADC.html)
and [ADC extension conventions](https://adc.sourceforge.io/ADC-EXT.html).
