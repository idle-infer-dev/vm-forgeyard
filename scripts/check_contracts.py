#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

from kvm_control.contracts.validation import ContractValidationError, validate_packaged_contracts


def main() -> int:
    try:
        result = validate_packaged_contracts()
    except ContractValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "capabilities_id": result.capabilities_id,
                "workflow_count": result.workflow_count,
                "workflow_ids": result.workflow_ids,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
