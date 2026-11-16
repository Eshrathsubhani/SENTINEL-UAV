# Protocol design

The simulator leg uses MAVLink. The gateway link uses mutually authenticated
TLS 1.3 over TCP. Use a supported TLS implementation and define message
framing, input size limits, timeouts, and reconnect behavior before integration.
Separate MAVLink signing is a later comparison configuration.

A mission request needs a request ID, vehicle ID, mission ID, operation, and
authenticated operator context. A response needs the request ID, decision,
reason, and observed simulator outcome when available. Scope deduplication
to the authenticated identity and operation. Specify retry behavior when an
operation was forwarded but acknowledgment is unavailable.

The current policy prototype uses east/north metres and sample and decision
times on a common clock. The SITL adapter must define the origin and time
mapping, including handling a simulator restart.
