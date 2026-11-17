"""Run static assessment against a scoped Git revision."""
import argparse
import json
import sys

from mallace.assessment.secrets import AssessmentScope, scan_secrets
from mallace.assessment.semgrep import SemgrepScope, scan_semgrep
from mallace.safety.json_boundary import load_json, read_bounded_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=("secrets", "semgrep"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--scope", required=True)
    args = parser.parse_args()
    try:
        scope_json = json.dumps(load_json(read_bounded_file(args.scope)))
        if args.scanner == "semgrep":
            result = scan_semgrep(args.source, SemgrepScope.model_validate_json(scope_json))
        else:
            result = scan_secrets(args.source, AssessmentScope.model_validate_json(scope_json))
    except Exception as exc:
        print(json.dumps({"status": "rejected", "error_type": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "completed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
