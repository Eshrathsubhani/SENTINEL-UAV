# Research methodology

1. Compare the same authenticated mission path with geographic authorization
   disabled and enabled. Measure policy outcomes, simulator state, and
   end-to-end latency under repeated runs.
2. Compare rules alone, Isolation Forest, Random Forest, and hybrid detection
   on the same held-out SITL scenarios. Fit Isolation Forest on normal runs
   and Random Forest on labeled runs. Use complete runs as split groups.
3. Compare gateway protection configurations under equivalent workloads with
   stated security properties. Report the transport used in each condition.

Fit preprocessing on training data and choose thresholds on a validation split.
Report per-class precision and recall, F1, false alerts on normal runs,
detection delay, and CPU and memory use. Keep public benchmarks separate
unless their feature definitions and labels are demonstrably compatible.
