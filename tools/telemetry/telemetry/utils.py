from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_percent(part: int | float, total: int | float) -> float:
    if not total:
        return 0.0
    return round((float(part) / float(total)) * 100.0, 2)


def round_float(value: Any, digits: int = 3) -> Any:
    if value is None:
        return None
    try:
        if math.isnan(float(value)) or math.isinf(float(value)):
            return None
        return round(float(value), digits)
    except (TypeError, ValueError):
        return value


def percentile(values: Iterable[float], p: float) -> float | None:
    sorted_values = sorted(float(v) for v in values if v is not None)
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return round_float(sorted_values[0])
    k = (len(sorted_values) - 1) * (p / 100.0)
    lower = math.floor(k)
    upper = math.ceil(k)
    if lower == upper:
        return round_float(sorted_values[int(k)])
    lower_value = sorted_values[lower]
    upper_value = sorted_values[upper]
    return round_float(lower_value + (upper_value - lower_value) * (k - lower))


def stats(values: Iterable[float]) -> dict[str, Any]:
    cleaned = [float(v) for v in values if v is not None]
    if not cleaned:
        return {"count": 0, "avg": None, "min": None, "max": None, "p50": None, "p95": None}
    return {
        "count": len(cleaned),
        "avg": round_float(sum(cleaned) / len(cleaned)),
        "min": round_float(min(cleaned)),
        "max": round_float(max(cleaned)),
        "p50": percentile(cleaned, 50),
        "p95": percentile(cleaned, 95),
    }


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    """Extract the first valid JSON object from mixed openssl/HTTP output."""
    if not text:
        return None

    start_positions = [m.start() for m in re.finditer(r"\{", text)]
    for start in start_positions:
        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : idx + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break
    return None


def json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False)
