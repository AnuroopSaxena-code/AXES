# Browser verification fixtures

- `workbench_smoke.py`: writes to stdout/stderr and emits a sample every 0.5 seconds for 30 seconds; suitable for reload recovery and cancellation checks.
- `workbench_compile.c`: valid source for compile/run verification.
- `workbench_invalid.c`: intentionally invalid source for compiler diagnostic verification; do not include it in normal build targets.

Use the workbench's Browse control to stage these files. They are test inputs, not automated assertions. Automated API regression tests are in `tests/test_workbench.py`.
