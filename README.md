# Mallace Public Edition

Mallace Public Edition checks committed Git source with local secret patterns and
a pinned Semgrep ruleset. It returns JSON findings and coverage. Findings are
unverified observations. Scan only repositories you have permission to assess.

Install in a dedicated Python 3.12+ environment with `pip install .`.
The secret scan needs Git. The Semgrep scan also needs Docker and the pinned
image listed in `mallace/assessment/semgrep.py`.

Create a JSON scope with your GitHub `repository` (owner/name), full 40-character
`revision`, a future ISO 8601 `expires_at` with timezone, and `paths` containing
the repository-relative files or folders to scan. The source checkout's origin
must match the scope. For Semgrep include
`"allowed_scanners": ["semgrep-1.184.0-mallace-code-v15"]`.

```sh
mallace-scan secrets --source /path/to/checkout --scope scope.json
mallace-scan semgrep --source /path/to/checkout --scope scope.json
```

Exit codes are 0 for a completed scan, 2 for rejected input, and 3 for a report
that did not complete. Scans inspect committed source at the scoped revision.
This edition covers static assessment.

Apache 2.0 applies to the public edition, with the existing MIT license retained
for inherited MIT portions. See LICENSE and LICENSE-MIT.
