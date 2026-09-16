# AirDC-I2P Threat Model

## Scope

AirDC-I2P is intended to carry Direct Connect hub and peer-transfer traffic
through an I2P router's local SAM interface. It does not claim absolute
anonymity and must not silently use a clearnet transport when I2P is unavailable.

## Protected Goals

The release target protects against:

* accidental IPv4 or IPv6 Direct Connect connections;
* normal DNS resolution for I2P hub or peer destinations;
* ordinary DC UDP search, results, NAT traversal and port mapping;
* publication of IP address and UDP port fields in ADC INF messages;
* clearnet CTM, RCM, NAT and RNT peer negotiation;
* accidental public exposure of the local Web UI or management API;
* accidental logging of a private I2P destination.

## Trust Boundaries

| Boundary | Rule |
| --- | --- |
| Application to SAM | The application may contact only a local, numeric loopback endpoint by default. A remote SAM bridge requires an explicit future opt-in because SAM is sensitive control traffic. |
| SAM to I2P | The local router provides I2P routing. Router failure closes or interrupts DC operations. |
| Hub to client | The hub carries ADC control messages but must not proxy file contents. |
| Client to client | Transfers use authenticated I2P streams and an I2P-specific ADC capability. |
| Identity storage | The private destination is stored with owner-only permissions on Unix and must never be emitted to normal logs or the Web UI. |

## Not Automatically Protected

I2P transport does not prevent identification through nicknames, chat,
deliberately shared personal information, shared file names, malicious files,
a compromised operating system, a compromised router, or vulnerabilities in
I2P or application dependencies. Users remain responsible for the metadata
they choose to publish.

## Fail-Closed Rule

If SAM connection, session creation, destination lookup, stream creation, or
stream acceptance fails, the affected operation fails with an I2P-specific
error. No direct socket retry is permitted.
