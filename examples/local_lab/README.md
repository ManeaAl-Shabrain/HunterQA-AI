# Isolated C research fixtures

These are *deliberately defective local examples*. Do not ship the binaries.

```bash
cd examples/local_lab
mkdir -p fuzz-input
printf 'FUZZ' > fuzz-input/start
AFL_LLVM_LAF_ALL=1 afl-clang-fast -g -O1 fuzz_target.c -o fuzz_target
AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 afl-fuzz -i fuzz-input -o fuzz-output -m 512 -t 1000 -V 120 -- ./fuzz_target
clang -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer uaf_test.c -o uaf_test_san
./uaf_test_san 2> uaf_sanitizer.log || true
```

Run fuzzing inside an isolated VM, not against live services. Research output is not automatically evidence of an exploitable security vulnerability. For replay, place the built binary and crash files in a configured approved local root and run `python -m hunterqa verify-crashes --help`.
