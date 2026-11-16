# Implementation details

Phase 1 keeps the existing policy prototype and documents the planned
interfaces. The logical folders represent future ownership and are created
without placeholder Python modules. Treat the root dependency list as the
initial candidate stack and record resolved versions after testing.

Phase 2 records telemetry in a standalone read-only process. It feeds the
policy local east/north coordinates. The demo area is an inclusive 100 m
square with a maximum sample age of two seconds. Use those settings for
baseline checks and version the configuration when changing them.
