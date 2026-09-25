# Known limitations

* **Benchmark realism.** OWASP Benchmark test cases are synthetic, single-file servlets. They are the best public dataset with complete ground truth and real scanner output, but real applications have cross-file flows and frameworks. Re-run on your own historically triaged findings (`ingest --checkmarx`) before trusting a policy in production.
* **The rules triager is simple.** Its 100% accuracy when it decides reflects that algorithm names and cookie flags are easy to read, not general intelligence. It is a baseline, not a product.
* **Scanner vintage.** The bundled FindSecBugs results are from 2016. Use a fresh SARIF run for current rule sets.
* **Labels from triage history inherit analyst error.** If your team mislabelled findings, the evaluation inherits that; sample and re-check labels for the categories you plan to automate.
* **Cost and rate limits.** 200 findings × 3 runs is 600 calls. Free API tiers throttle; the client backs off and the cache lets you resume.
