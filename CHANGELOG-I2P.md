# AirDC-I2P Changelog

## Unreleased

* Forked AirDC++ Web Client at `56bf01a929d68e11fca1445e73207995727a50e1`.
* Added the initial architecture, threat-model, and network-audit records.
* Recorded the Ubuntu 24.04 baseline: AirDC++ Core builds; the full Web API
  build is blocked by websocketpp's C++20-incompatible constructor syntax.
* Added a strict numeric-loopback SAM v3.1 client transport with long-lived
  STREAM sessions, independent incoming/outgoing virtual streams, persistent
  private destinations, and no hostname resolution at the SAM boundary.
* Added a Linux integration test with a local fake SAM bridge covering identity
  persistence and permissions, control-session setup, lookup, stream data, and
  SAM 3.2 keepalives.
