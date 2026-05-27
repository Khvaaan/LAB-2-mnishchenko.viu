import concurrent.futures
import json
import re
import threading
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


TASK_1_FILE = "result_task_1.json"
OUT_FILE = "result_task_2.json"
ERROR_FILE = "task_2_errors.json"
MISSING_FILE = "task_2_missing_data.json"

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"

MAX_WORKERS = 8
TIMEOUT = (5, 40)

HEADERS = {
    "User-Agent": "Mozilla/5.0 vuln-lab-2"
}

THREAD_LOCAL = threading.local()
CWE_CACHE = {}
CWE_CACHE_LOCK = threading.Lock()


def make_session() -> requests.Session:
    session = requests.Session()

    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(HEADERS)

    return session


def get_session() -> requests.Session:
    if not hasattr(THREAD_LOCAL, "session"):
        THREAD_LOCAL.session = make_session()
    return THREAD_LOCAL.session


def request_json(url: str) -> dict:
    response = get_session().get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def to_iso_date(value: Any) -> str:
    if not value:
        return ""

    text = str(value).strip()

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).date().isoformat()
    except Exception:
        return text[:10]


def fetch_mitre_cve(cve_id: str) -> dict:
    return request_json(CVE_API_URL.format(cve_id=cve_id))


def get_english_description(descriptions: list[dict]) -> str:
    for item in descriptions or []:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]

    for item in descriptions or []:
        if item.get("value"):
            return item["value"]

    return ""


def get_mitre_description(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    return get_english_description(cna.get("descriptions", []))


def normalize_cvss_version(key: str) -> str:
    key = key.lower().replace("_", "")

    mapping = {
        "cvssv40": "cvss40",
        "cvssv31": "cvss31",
        "cvssv30": "cvss30",
        "cvssv2": "cvss20",
    }

    return mapping.get(key, key)

def collect_cvss(record: dict) -> list[dict]:
    result = []

    containers = record.get("containers", {})
    all_containers = []

    if containers.get("cna"):
        all_containers.append(containers["cna"])

    all_containers.extend(containers.get("adp", []) or [])

    for container in all_containers:
        for metric in container.get("metrics", []) or []:
            for key, value in metric.items():
                if not key.lower().startswith("cvss"):
                    continue

                if not isinstance(value, dict):
                    continue

                item = {
                    "version": normalize_cvss_version(key),
                    "score": value.get("baseScore"),
                    "vector": value.get("vectorString", ""),
                    "severity": value.get("baseSeverity") or value.get("severity") or ""
                }

                if item["score"] is not None and item["vector"]:
                    result.append(item)

    return dedupe_dicts(result, ["version", "score", "vector", "severity"])


DEFAULT_CPE_VENDOR = "adobe"
DEFAULT_CPE_PRODUCT = "photoshop"

NO_VALUE_MARKERS = {
    "",
    "*",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "unspecified",
    "not available",
}


def has_real_value(value: Any) -> bool:
    if value is None:
        return False

    text = str(value).strip().lower()
    return text not in NO_VALUE_MARKERS


def clean_version(value: Any) -> str:
    return str(value).strip().strip(" .,;:)]}")


def normalize_cpe_part(value: Any) -> str:
    if not has_real_value(value):
        return "*"

    value = str(value).strip().lower()

    value = value.replace(" ", "_")
    value = value.replace("\\", "_")
    value = value.replace("/", "_")
    value = value.replace(":", "_")

    return quote(value, safe="._-*")


def version_data_is_usable(version_data: dict) -> bool:
    raw_version = str(version_data.get("version", "")).lower()

    if "photoshop" in raw_version:
        return False

    if "," in raw_version and "earlier" in raw_version:
        return False

    return (
        has_real_value(version_data.get("version"))
        or has_real_value(version_data.get("lessThan"))
        or has_real_value(version_data.get("lessThanOrEqual"))
    )


def build_cpe(vendor: str, product: str, version_data: dict) -> str | None:
    vendor = vendor if has_real_value(vendor) else DEFAULT_CPE_VENDOR
    product = product if has_real_value(product) else DEFAULT_CPE_PRODUCT

    # Так как выбран конкретный продукт Adobe Photoshop,
    # любые длинные описания продукта нормализуем до photoshop.
    product_text = str(product).lower()
    if "photoshop" in product_text or len(product_text) > 40:
        product = DEFAULT_CPE_PRODUCT

    version = version_data.get("version") or "*"

    if not has_real_value(version):
        version = "*"

    less_than = version_data.get("lessThan")
    less_than_or_equal = version_data.get("lessThanOrEqual")

    if has_real_value(less_than):
        version = f"{version}_before_{clean_version(less_than)}"
    elif has_real_value(less_than_or_equal):
        version = f"{version}_through_{clean_version(less_than_or_equal)}"

    # Не создаём бесполезный CPE вида cpe:2.3:a:*:*:*...
    if not has_real_value(version):
        return None

    if version == "*":
        return None

    vendor = normalize_cpe_part(vendor)
    product = normalize_cpe_part(product)
    version = normalize_cpe_part(version)

    if vendor == "*" or product == "*" or version == "*":
        return None

    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def dedupe_versions(versions: list[dict]) -> list[dict]:
    result = []
    seen = set()

    for item in versions:
        key = (
            str(item.get("version", "")),
            str(item.get("lessThan", "")),
            str(item.get("lessThanOrEqual", "")),
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


def extract_versions_from_text(text: str) -> list[dict]:
    """
    MITRE CVE API для старых CVE часто хранит версии только в описании,
    например:
    - Photoshop CC 2014 before 15.2.4
    - Photoshop CC 2017 (18.0.1) and earlier

    Здесь вытаскиваем такие версии из текста.
    """
    if not text or "photoshop" not in text.lower():
        return []

    versions = []

    before_patterns = [
        r"(?i)photoshop.{0,120}?(?:before|prior to)\s+([0-9][0-9A-Za-z._-]*)",
        r"(?i)(?:before|prior to)\s+([0-9][0-9A-Za-z._-]*)",
    ]

    through_patterns = [
        r"(?i)photoshop.{0,120}?\(([0-9][0-9A-Za-z._-]*)\)\s+(?:and\s+)?earlier",
        r"(?i)\(([0-9][0-9A-Za-z._-]*)\)\s+(?:and\s+)?earlier",
        r"(?i)\b([0-9]+(?:\.[0-9A-Za-z_-]+)+)\s+(?:and\s+)?earlier",
    ]

    for pattern in before_patterns:
        for match in re.finditer(pattern, text):
            versions.append({
                "version": "*",
                "lessThan": clean_version(match.group(1)),
                "status": "affected",
            })

    for pattern in through_patterns:
        for match in re.finditer(pattern, text):
            versions.append({
                "version": "*",
                "lessThanOrEqual": clean_version(match.group(1)),
                "status": "affected",
            })

    return dedupe_versions(versions)


def get_affected_text(affected: dict) -> str:
    return json.dumps(affected, ensure_ascii=False)


def collect_cpe_list(record: dict) -> list[str]:
    cpes = set()
    description = get_mitre_description(record)

    containers = record.get("containers", {})
    all_containers = []

    if containers.get("cna"):
        all_containers.append(containers["cna"])

    all_containers.extend(containers.get("adp", []) or [])

    for container in all_containers:
        for affected in container.get("affected", []) or []:
            affected_text = get_affected_text(affected)
            related_text = f"{affected_text} {description}"

            # Для этой лабы собираем CPE только по выбранному продукту.
            if "photoshop" not in related_text.lower():
                continue

            vendor = affected.get("vendor", "")
            product = affected.get("product", "")

            if not has_real_value(vendor) or str(vendor).lower() in {"adobe systems incorporated"}:
                vendor = DEFAULT_CPE_VENDOR

            if not has_real_value(product) or "photoshop" in str(product).lower() or len(str(product)) > 40:
                product = DEFAULT_CPE_PRODUCT

            for raw_cpe in affected.get("cpes", []) or []:
                # Готовый CPE берём только если он не пустой по vendor/product/version.
                parts = raw_cpe.split(":")
                if len(parts) >= 6 and parts[3] != "*" and parts[4] != "*" and parts[5] != "*":
                    cpes.add(raw_cpe)

            version_candidates = []

            for version_data in affected.get("versions", []) or []:
                status = str(version_data.get("status", "")).lower()

                if status and status not in {"affected", "unknown"}:
                    continue

                if version_data_is_usable(version_data):
                    version_candidates.append(version_data)

            # Если версии в нормальных полях нет, пытаемся достать её из текста affected/description.
            if not version_candidates:
                version_candidates = extract_versions_from_text(related_text)

            for version_data in dedupe_versions(version_candidates):
                cpe = build_cpe(vendor, product, version_data)
                if cpe:
                    cpes.add(cpe)

    # Последний fallback: если affected пустой или кривой, пробуем описание CVE.
    if not cpes:
        desc_lower = description.lower()

        # Пример из MITRE:
        # "Adobe Photoshop versions Photoshop CC 2019, and Photoshop 2020 ..."
        if "photoshop cc 2019" in desc_lower:
            cpe = build_cpe(DEFAULT_CPE_VENDOR, DEFAULT_CPE_PRODUCT, {
                "version": "cc_2019",
                "status": "affected",
            })
            if cpe:
                cpes.add(cpe)

        if "photoshop 2020" in desc_lower:
            cpe = build_cpe(DEFAULT_CPE_VENDOR, DEFAULT_CPE_PRODUCT, {
                "version": "2020",
                "status": "affected",
            })
            if cpe:
                cpes.add(cpe)

        # Пример:
        # "Adobe Bridge version 11.0.2 (and earlier) ..."
        bridge_match = re.search(
            r"(?i)adobe bridge version\s+([0-9][0-9A-Za-z._-]*)\s*\(?(?:and\s+)?earlier\)?",
            description
        )
        if bridge_match:
            cpe = build_cpe(DEFAULT_CPE_VENDOR, "bridge", {
                "version": "*",
                "lessThanOrEqual": clean_version(bridge_match.group(1)),
                "status": "affected",
            })
            if cpe:
                cpes.add(cpe)

        for version_data in extract_versions_from_text(description):
            cpe = build_cpe(DEFAULT_CPE_VENDOR, DEFAULT_CPE_PRODUCT, version_data)
            if cpe:
                cpes.add(cpe)

    return sorted(cpes)


def collect_cwe_ids(record: dict) -> list[str]:
    cwe_ids = set()
    cwe_re = re.compile(r"CWE-\d+", re.IGNORECASE)

    containers = record.get("containers", {})
    all_containers = []

    if containers.get("cna"):
        all_containers.append(containers["cna"])

    all_containers.extend(containers.get("adp", []) or [])

    for container in all_containers:
        for problem_type in container.get("problemTypes", []) or []:
            for desc in problem_type.get("descriptions", []) or []:
                cwe_id = desc.get("cweId")

                if cwe_id and cwe_re.fullmatch(cwe_id):
                    cwe_ids.add(cwe_id.upper())

                text = " ".join(str(v) for v in desc.values() if v)

                for found in cwe_re.findall(text):
                    cwe_ids.add(found.upper())

    return sorted(cwe_ids)


def find_first_weakness_object(data: Any) -> dict | None:
    if isinstance(data, dict):
        keys = {k.lower() for k in data.keys()}

        if "id" in keys and ("name" in keys or "description" in keys):
            return data

        for value in data.values():
            found = find_first_weakness_object(value)
            if found:
                return found

    elif isinstance(data, list):
        for item in data:
            found = find_first_weakness_object(item)
            if found:
                return found

    return None


def fetch_cwe_info(cwe_id: str) -> dict:
    with CWE_CACHE_LOCK:
        if cwe_id in CWE_CACHE:
            return CWE_CACHE[cwe_id]

    match = re.fullmatch(r"CWE-(\d+)", cwe_id, flags=re.IGNORECASE)

    if not match:
        result = {
            "name": cwe_id,
            "description": "CWE information is not available in MITRE CWE API."
        }

        with CWE_CACHE_LOCK:
            CWE_CACHE[cwe_id] = result

        return result

    cwe_num = match.group(1)

    try:
        data = request_json(CWE_API_URL.format(cwe_num=cwe_num))
        item = find_first_weakness_object(data) or {}

        name = (
            item.get("Name")
            or item.get("name")
            or item.get("Title")
            or item.get("title")
            or f"CWE-{cwe_num}"
        )

        description = (
            item.get("Description")
            or item.get("description")
            or item.get("Description_Summary")
            or item.get("description_summary")
            or ""
        )

        if not description and cwe_num == "189":
            name = "Numeric Errors"
            description = (
                "Weaknesses in this category are related to improper calculation "
                "or conversion of numbers."
            )

        if not description:
            description = "CWE description is not available in MITRE CWE API."

        result = {
            "name": str(name),
            "description": str(description)
        }

    except Exception:
        if cwe_num == "189":
            result = {
                "name": "Numeric Errors",
                "description": (
                    "Weaknesses in this category are related to improper calculation "
                    "or conversion of numbers."
                )
            }
        else:
            result = {
                "name": f"CWE-{cwe_num}",
                "description": "CWE description is not available in MITRE CWE API."
            }

    with CWE_CACHE_LOCK:
        CWE_CACHE[cwe_id] = result

    return result


def dedupe_dicts(items: list[dict], keys: list[str]) -> list[dict]:
    seen = set()
    result = []

    for item in items:
        key = tuple(str(item.get(k, "")) for k in keys)

        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


def enrich_item(item: dict) -> dict:
    cve_id = item["ID"]

    record = fetch_mitre_cve(cve_id)
    cve_meta = record.get("cveMetadata", {}) or {}

    cwe = {}
    for cwe_id in collect_cwe_ids(record):
        cwe[cwe_id] = fetch_cwe_info(cwe_id)

    return {
        "ID": cve_id,
        "vendor_release_date": item.get("vendor_release_date", ""),
        "vendor_release_url": item.get("vendor_release_url", ""),
        "url": CVE_ORG_URL.format(cve_id=cve_id),
        "published_date": to_iso_date(cve_meta.get("datePublished")),
        "updated_date": to_iso_date(cve_meta.get("dateUpdated")),
        "description": get_mitre_description(record),
        "cvss_list": collect_cvss(record),
        "cpe_list": collect_cpe_list(record),
        "cwe": cwe
    }


def find_missing_data(item: dict) -> list[str]:
    missing = []

    first_level_fields = [
        "ID",
        "vendor_release_date",
        "vendor_release_url",
        "url",
        "published_date",
        "updated_date",
        "description",
    ]

    for field in first_level_fields:
        if not item.get(field):
            missing.append(field)

    if not item.get("cvss_list"):
        missing.append("cvss_list")

    if not item.get("cpe_list"):
        missing.append("cpe_list")

    if not item.get("cwe"):
        missing.append("cwe")

    return missing


def main():
    with open(TASK_1_FILE, "r", encoding="utf-8") as f:
        task_1_items = json.load(f)

    result = []
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(enrich_item, item): item
            for item in task_1_items
        }

        total = len(future_map)

        for index, future in enumerate(concurrent.futures.as_completed(future_map), start=1):
            source_item = future_map[future]
            cve_id = source_item.get("ID", "")

            try:
                enriched = future.result()
                result.append(enriched)

                print(
                    f"[OK] {index}/{total} {cve_id} "
                    f"cvss={len(enriched['cvss_list'])} "
                    f"cpe={len(enriched['cpe_list'])} "
                    f"cwe={len(enriched['cwe'])}"
                )

            except Exception as e:
                print(f"[SKIP] {index}/{total} {cve_id}: {e}")
                errors.append({
                    "ID": cve_id,
                    "error": str(e)
                })

    result = sorted(result, key=lambda x: (x["vendor_release_date"], x["ID"]))

    missing_data = []
    for item in result:
        missing = find_missing_data(item)
        if missing:
            missing_data.append({
                "ID": item["ID"],
                "missing_fields": missing
            })

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    if errors:
        with open(ERROR_FILE, "w", encoding="utf-8") as f:
            json.dump(errors, f, ensure_ascii=False, indent=2)

    if missing_data:
        with open(MISSING_FILE, "w", encoding="utf-8") as f:
            json.dump(missing_data, f, ensure_ascii=False, indent=2)

    print(f"Готово. Записано: {len(result)}")
    print(f"Ошибок: {len(errors)}")
    print(f"Неполных записей: {len(missing_data)}")
    print(f"Файл: {OUT_FILE}")


if __name__ == "__main__":
    main()
