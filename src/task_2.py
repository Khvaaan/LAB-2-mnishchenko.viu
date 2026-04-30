import json
import os
import re
import time
from datetime import datetime
from typing import Any

import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser


TASK_1_FILE = "result_task_1.json"
OUT_FILE = "result_task_2.json"

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={cve_id}"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"
CWE_HTML_URL = "https://cwe.mitre.org/data/definitions/{cwe_num}.html"

HEADERS = {
    "User-Agent": "Mozilla/5.0 vuln-lab-2"
}

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_SLEEP = float(os.getenv("NVD_SLEEP", "6.2"))


def to_iso_date(value: Any) -> str:
    if not value:
        return ""

    try:
        return date_parser.parse(str(value)).date().isoformat()
    except Exception:
        return str(value)


def request_json(url: str, *, params: dict | None = None, headers: dict | None = None) -> dict:
    final_headers = dict(HEADERS)

    if headers:
        final_headers.update(headers)

    for attempt in range(5):
        response = requests.get(url, params=params, headers=final_headers, timeout=60)

        if response.status_code == 429:
            wait_sec = 10 + attempt * 5
            print(f"  429 rate limit, sleep {wait_sec}s")
            time.sleep(wait_sec)
            continue

        response.raise_for_status()
        return response.json()

    raise RuntimeError(f"Не удалось получить JSON: {url}")


def fetch_mitre_cve(cve_id: str) -> dict:
    return request_json(CVE_API_URL.format(cve_id=cve_id))


def fetch_nvd_cve(cve_id: str) -> dict:
    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    data = request_json(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=headers
    )

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}

    return vulns[0].get("cve", {})


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


def get_nvd_description(nvd_cve: dict) -> str:
    return get_english_description(nvd_cve.get("descriptions", []))


def normalize_cvss_version(key: str) -> str:
    return key.lower().replace("_", "")


def collect_mitre_cvss(record: dict) -> list[dict]:
    result = []
    containers = record.get("containers", {})

    all_containers = []
    if containers.get("cna"):
        all_containers.append(containers["cna"])

    all_containers.extend(containers.get("adp", []))

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

                if item["score"] is not None or item["vector"]:
                    result.append(item)

    return dedupe_dicts(result, ["version", "score", "vector", "severity"])


def collect_nvd_cvss(nvd_cve: dict) -> list[dict]:
    result = []
    metrics = nvd_cve.get("metrics", {}) or {}

    version_map = {
        "cvssMetricV40": "cvss40",
        "cvssMetricV31": "cvss31",
        "cvssMetricV30": "cvss30",
        "cvssMetricV2": "cvss20",
    }

    for metric_key, version in version_map.items():
        for item in metrics.get(metric_key, []) or []:
            cvss_data = item.get("cvssData", {}) or {}

            result.append({
                "version": version,
                "score": cvss_data.get("baseScore"),
                "vector": cvss_data.get("vectorString", ""),
                "severity": item.get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            })

    return dedupe_dicts(result, ["version", "score", "vector", "severity"])


def collect_mitre_cpes(record: dict) -> list[str]:
    cpes = set()
    containers = record.get("containers", {})

    all_containers = []
    if containers.get("cna"):
        all_containers.append(containers["cna"])
    all_containers.extend(containers.get("adp", []))

    for container in all_containers:
        for affected in container.get("affected", []) or []:
            for cpe in affected.get("cpes", []) or []:
                if cpe:
                    cpes.add(cpe)

    return sorted(cpes)


def walk_nvd_nodes(nodes: list[dict]) -> list[str]:
    cpes = []

    for node in nodes or []:
        for match in node.get("cpeMatch", []) or []:
            criteria = match.get("criteria")
            if criteria:
                cpes.append(criteria)

        cpes.extend(walk_nvd_nodes(node.get("nodes", []) or []))

    return cpes


def collect_nvd_cpes(nvd_cve: dict) -> list[str]:
    cpes = []

    for config in nvd_cve.get("configurations", []) or []:
        cpes.extend(walk_nvd_nodes(config.get("nodes", []) or []))

    return sorted(set(cpes))


def collect_mitre_cwe_ids(record: dict) -> list[str]:
    cwe_ids = set()
    cwe_re = re.compile(r"CWE-\d+", re.IGNORECASE)

    containers = record.get("containers", {})

    all_containers = []
    if containers.get("cna"):
        all_containers.append(containers["cna"])
    all_containers.extend(containers.get("adp", []))

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


def collect_nvd_cwe_ids(nvd_cve: dict) -> list[str]:
    cwe_ids = set()

    for weakness in nvd_cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "")

            if re.fullmatch(r"CWE-\d+", value, flags=re.IGNORECASE):
                cwe_ids.add(value.upper())

    return sorted(cwe_ids)


def extract_first_dict_with_keys(data: Any, required_keys: set[str]) -> dict | None:
    if isinstance(data, dict):
        lowered = {k.lower(): k for k in data.keys()}
        if all(key.lower() in lowered for key in required_keys):
            return data

        for value in data.values():
            found = extract_first_dict_with_keys(value, required_keys)
            if found:
                return found

    elif isinstance(data, list):
        for item in data:
            found = extract_first_dict_with_keys(item, required_keys)
            if found:
                return found

    return None


def fetch_cwe_info(cwe_id: str) -> dict:
    match = re.fullmatch(r"CWE-(\d+)", cwe_id, flags=re.IGNORECASE)
    if not match:
        return {
            "name": cwe_id,
            "description": "CWE information is not available"
        }

    cwe_num = match.group(1)

    # 1) Пробуем официальный CWE REST API
    try:
        data = request_json(CWE_API_URL.format(cwe_num=cwe_num))
        item = extract_first_dict_with_keys(data, {"ID"}) or {}

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

        if name or description:
            return {
                "name": str(name),
                "description": str(description)
            }
    except Exception:
        pass

    # 2) Fallback: HTML-страница CWE
    try:
        url = CWE_HTML_URL.format(cwe_num=cwe_num)
        response = requests.get(url, headers=HEADERS, timeout=60)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "lxml")
        title = soup.get_text("\n", strip=True).splitlines()[0]
        page_title = soup.title.get_text(" ", strip=True) if soup.title else title

        name_match = re.search(rf"CWE-{cwe_num}:\s*(.*?)\s*(?:\(|$)", page_title)
        name = name_match.group(1).strip() if name_match else f"CWE-{cwe_num}"

        text = soup.get_text("\n", strip=True)
        description = ""

        if "Description" in text:
            fragment = text.split("Description", 1)[1]
            for stop in ["Extended Description", "Common Consequences", "Relationships"]:
                if stop in fragment:
                    fragment = fragment.split(stop, 1)[0]
            description = " ".join(fragment.split())[:2000]

        return {
            "name": name,
            "description": description
        }
    except Exception:
        return {
            "name": f"CWE-{cwe_num}",
            "description": ""
        }


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


def merge_cvss(mitre_cvss: list[dict], nvd_cvss: list[dict]) -> list[dict]:
    merged = mitre_cvss + nvd_cvss
    return dedupe_dicts(merged, ["version", "score", "vector", "severity"])


def enrich_item(item: dict) -> dict:
    cve_id = item["ID"]

    print(f"[FETCH] {cve_id}")

    mitre_record = fetch_mitre_cve(cve_id)

    try:
        nvd_cve = fetch_nvd_cve(cve_id)
    except Exception as e:
        print(f"  [WARN] NVD fallback failed for {cve_id}: {e}")
        nvd_cve = {}

    cve_meta = mitre_record.get("cveMetadata", {}) or {}

    description = get_mitre_description(mitre_record) or get_nvd_description(nvd_cve)

    cvss_list = merge_cvss(
        collect_mitre_cvss(mitre_record),
        collect_nvd_cvss(nvd_cve)
    )

    cpe_list = sorted(set(
        collect_mitre_cpes(mitre_record)
        + collect_nvd_cpes(nvd_cve)
    ))

    cwe_ids = sorted(set(
        collect_mitre_cwe_ids(mitre_record)
        + collect_nvd_cwe_ids(nvd_cve)
    ))

    cwe = {}
    for cwe_id in cwe_ids:
        cwe[cwe_id] = fetch_cwe_info(cwe_id)

    return {
        "ID": cve_id,
        "vendor_release_date": item.get("vendor_release_date", ""),
        "vendor_release_url": item.get("vendor_release_url", ""),
        "url": CVE_ORG_URL.format(cve_id=cve_id),
        "published_date": to_iso_date(cve_meta.get("datePublished") or nvd_cve.get("published")),
        "updated_date": to_iso_date(cve_meta.get("dateUpdated") or nvd_cve.get("lastModified")),
        "description": description,
        "cvss_list": cvss_list,
        "cpe_list": cpe_list,
        "cwe": cwe
    }


def main():
    with open(TASK_1_FILE, "r", encoding="utf-8") as f:
        task_1_items = json.load(f)

    result = []

    for index, item in enumerate(task_1_items, start=1):
        try:
            enriched = enrich_item(item)
            result.append(enriched)

            print(
                f"[OK] {index}/{len(task_1_items)} "
                f"{enriched['ID']} "
                f"cvss={len(enriched['cvss_list'])} "
                f"cpe={len(enriched['cpe_list'])} "
                f"cwe={len(enriched['cwe'])}"
            )
        except Exception as e:
            print(f"[SKIP] {item.get('ID')}: {e}")

        time.sleep(NVD_SLEEP)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"Готово. Записано: {len(result)}")
    print(f"Файл: {OUT_FILE}")


if __name__ == "__main__":
    main()
