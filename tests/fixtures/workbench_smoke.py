import sys, time
print('AXES workbench verification: stdout', flush=True)
print('AXES workbench verification: stderr', file=sys.stderr, flush=True)
for i in range(60):
    print('sample', i, flush=True)
    time.sleep(0.5)
