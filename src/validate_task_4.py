import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


DATA_FILE = Path("result_task_2.json")
SCHEMA_FILE = Path("json_schema.json")
ERROR_REPORT_FILE = Path("report_task_4_validation_errors.json")


def json_path(error) -> str:
    if not error.absolute_path:
        return "$"

    result = "$"
    for part in error.absolute_path:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f".{part}"
    return result


def main():
    with DATA_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    with SCHEMA_FILE.open("r", encoding="utf-8") as f:
        schema = json.load(f)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker()
    )

    errors = sorted(
        validator.iter_errors(data),
        key=lambda e: list(e.absolute_path)
    )

    if not errors:
        print("OK: result_task_2.json проходит проверку по json_schema.json")
        return 0

    report = []

    print(f"VALIDATION FAILED: найдено ошибок: {len(errors)}")

    for error in errors:
        item = {
            "path": json_path(error),
            "message": error.message,
            "validator": error.validator
        }
        report.append(item)
        print(f"- {item['path']}: {item['message']}")

    with ERROR_REPORT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\nОтчёт об ошибках сохранён в {ERROR_REPORT_FILE}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
