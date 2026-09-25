| Triager | Model | Findings | Runs | False dismissals (95% upper) | Noise removed | Abstained | Accuracy when decided | Consistency |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| scanner-as-is | - | 2112 | 1 | 0.0% (0.3%) | 0.0% | 0.0% | 64.9% | 100.0% |
| rules | - | 2112 | 1 | 0.0% (0.3%) | 12.5% | 73.2% | 100.0% | 100.0% |

Policy for `rules` :

| Category | Mode | Reason |
|---|---|---|
| OS command injection | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Weak cryptography | Auto-dismiss | false-dismissal upper bound 2.9%, removes 100% of noise, consistency 100% |
| Weak hash | Analyst decides | scanner produced no false positives here: nothing for AI to remove |
| LDAP injection | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Path traversal | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Cookie without Secure flag | Analyst decides | scanner produced no false positives here: nothing for AI to remove |
| SQL injection | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Trust boundary violation | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Weak randomness | Analyst decides | scanner produced no false positives here: nothing for AI to remove |
| XPath injection | Analyst decides | triager abstained on 100%: it cannot decide this category |
| Cross-site scripting | Analyst decides | triager abstained on 100%: it cannot decide this category |
