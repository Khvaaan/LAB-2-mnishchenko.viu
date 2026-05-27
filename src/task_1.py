import concurrent.futures
import json
import re
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


INDEX_URL = "https://helpx.adobe.com/security/security-bulletin.html"
PRODUCT_NAME = "Adobe Photoshop"
OUT_FILE = "result_task_1.json"
ERROR_FILE = "task_1_errors.json"

MAX_WORKERS = 10
TIMEOUT = (5, 60)

HEADERS = {
    "User-Agent": "Mozilla/5.0 vuln-lab-2"
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

DATE_RE = re.compile(
    r"("
    r"[A-Z][a-z]+ \d{1,2}, \d{4}"
    r"|"
    r"[A-Z][a-z]{2} \d{1,2}, \d{4}"
    r"|"
    r"\d{1,2}/\d{1,2}/\d{2,4}"
    r")"
)

DATE_FORMATS = [
    "%B %d, %Y",   # November 11, 2025
    "%b %d, %Y",   # Nov 11, 2025
    "%m/%d/%Y",
    "%m/%d/%y",
]


def make_session() -> requests.Session:
    session = requests.Session()

    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=1.5,
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


def get_html(url: str) -> str:
    session = make_session()
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    return response.text


def parse_date_to_iso(date_text: str) -> str:
    date_text = date_text.replace("\xa0", " ").strip()

    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(date_text, fmt).date().isoformat()
        except ValueError:
            continue

    raise ValueError(f"Не удалось распарсить дату: {date_text}")


def extract_first_date(text: str) -> str:
    match = DATE_RE.search(text)
    if not match:
        return ""

    try:
        return parse_date_to_iso(match.group(1))
    except ValueError:
        return ""


def find_product_heading(soup: BeautifulSoup) -> Tag | None:
    for tag in soup.find_all(["h2", "h3", "h4"]):
        if tag.get_text(" ", strip=True).lower() == PRODUCT_NAME.lower():
            return tag
    return None


def extract_date_near_link(link: Tag) -> str:
    """
    Достаёт дату из строки таблицы или ближайшего блока вокруг ссылки.
    Это нужно как fallback, если на странице бюллетеня дата размечена иначе.
    """
    row = link.find_parent("tr")
    if row:
        date = extract_first_date(row.get_text(" ", strip=True))
        if date:
            return date

    parent = link.parent
    if isinstance(parent, Tag):
        date = extract_first_date(parent.get_text(" ", strip=True))
        if date:
            return date

    return ""


def find_photoshop_bulletins(index_html: str) -> list[dict]:
    soup = BeautifulSoup(index_html, "lxml")
    heading = find_product_heading(soup)

    bulletins = []

    if heading:
        for node in heading.find_all_next():
            if node is heading:
                continue

            if isinstance(node, Tag) and node.name in ["h2", "h3"]:
                break

            if not isinstance(node, Tag) or node.name != "a":
                continue

            href = node.get("href", "")
            text = node.get_text(" ", strip=True)

            if "APSB" not in text.upper() and "apsb" not in href.lower():
                continue

            full_url = urljoin(INDEX_URL, href)

            bulletins.append({
                "url": full_url,
                "index_date": extract_date_near_link(node)
            })

    # Fallback, если Adobe поменяет структуру раздела.
    if not bulletins:
        for link in soup.find_all("a", href=True):
            text = link.get_text(" ", strip=True).lower()
            href = link["href"].lower()

            if (
                "photoshop" in text
                and "elements" not in text
                and "album" not in text
                and ("apsb" in text or "apsb" in href)
            ):
                bulletins.append({
                    "url": urljoin(INDEX_URL, link["href"]),
                    "index_date": extract_date_near_link(link)
                })

    unique = {}
    for item in bulletins:
        unique[item["url"]] = item

    return list(unique.values())


def extract_date_from_bulletin_page(page_text: str, fallback_date: str = "") -> str:
    lower_text = page_text.lower()

    markers = [
        "date published",
        "originally posted",
        "last updated",
        "published",
    ]

    for marker in markers:
        pos = lower_text.find(marker)
        if pos != -1:
            fragment = page_text[pos:pos + 1000]
            date = extract_first_date(fragment)
            if date:
                return date

    date = extract_first_date(page_text)
    if date:
        return date

    if fallback_date:
        return fallback_date

    raise ValueError("Дата публикации не найдена")


def parse_bulletin(bulletin: dict) -> list[dict]:
    url = bulletin["url"]
    fallback_date = bulletin.get("index_date", "")

    html = get_html(url)
    soup = BeautifulSoup(html, "lxml")
    page_text = soup.get_text("\n", strip=True)

    cve_ids = sorted(set(cve.upper() for cve in CVE_RE.findall(page_text)))

    if not cve_ids:
        return []

    release_date = extract_date_from_bulletin_page(
        page_text=page_text,
        fallback_date=fallback_date,
    )

    return [
        {
            "ID": cve_id,
            "vendor_release_date": release_date,
            "vendor_release_url": url
        }
        for cve_id in cve_ids
    ]


def main():
    index_html = get_html(INDEX_URL)
    bulletins = find_photoshop_bulletins(index_html)

    print(f"Найдено бюллетеней Adobe Photoshop: {len(bulletins)}")

    result = []
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(parse_bulletin, bulletin): bulletin
            for bulletin in bulletins
        }

        total = len(future_map)

        for index, future in enumerate(concurrent.futures.as_completed(future_map), start=1):
            bulletin = future_map[future]
            url = bulletin["url"]

            try:
                items = future.result()
                result.extend(items)
                print(f"[OK] {index}/{total} {url} -> {len(items)} CVE")
            except Exception as e:
                print(f"[SKIP] {index}/{total} {url}: {e}")
                errors.append({
                    "url": url,
                    "error": str(e)
                })

    unique = {}
    for item in result:
        key = (item["ID"], item["vendor_release_url"])
        unique[key] = item

    result = sorted(
        unique.values(),
        key=lambda x: (x["vendor_release_date"], x["ID"], x["vendor_release_url"])
    )

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    if errors:
        with open(ERROR_FILE, "w", encoding="utf-8") as f:
            json.dump(errors, f, ensure_ascii=False, indent=2)

    print(f"Готово. CVE записано: {len(result)}")
    print(f"Ошибок: {len(errors)}")
    print(f"Файл: {OUT_FILE}")


if __name__ == "__main__":
    main()
