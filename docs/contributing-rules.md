# Contributing Rules and Benchmarks

When adding a new security rule:
1. Define the rule in `secskill/rules/<language>.yaml`.
2. Add at least one vulnerable sample in `benchmarks/vulnerable_samples/`.
3. Add a corresponding safe sample in `benchmarks/secure_samples/`.
4. Update `benchmarks/ground_truth.json`.
