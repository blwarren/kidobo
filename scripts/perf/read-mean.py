"""Read and validate a Criterion mean point estimate for local development checks."""

import json
import math
import sys
from pathlib import Path


def mean_estimate(path: Path) -> float:
    """Return a finite, positive mean from a bounded Criterion estimates file."""
    with path.open("rb") as source:
        contents = source.read(65_537)
    if len(contents) > 65_536:
        raise ValueError("estimates file exceeds 64 KiB")
    document: object = json.loads(contents)
    if not isinstance(document, dict) or not isinstance(document.get("mean"), dict):
        raise TypeError("missing mean object")
    value = document["mean"].get("point_estimate")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("mean.point_estimate must be finite and positive")
    return float(value)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: read-mean.py ESTIMATES_JSON")
    try:
        print(format(mean_estimate(Path(sys.argv[1])), ".17g"))
    except (OSError, ValueError, TypeError, OverflowError) as error:
        raise SystemExit(
            f"invalid Criterion estimates {sys.argv[1]}: {error}"
        ) from error
