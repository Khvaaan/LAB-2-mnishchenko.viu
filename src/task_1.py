import json
import re
import time
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, Tag


INDEX_URL = "https://helpx.adobe.com/security/security-bulletin.html"
PRODUCT_NAME = "Adobe Photoshop"
OUT_FILE = "result_task_1.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

DATE_RE = re.compile(
    r"([A-Z][a-z]+ \d{1,2}, \d{4}|\d{1,2}/\d{1,2}/\d{2,4})"
)

DATE_FORMATS = [
    "%B %d, %Y",   # November 11, 2025
    "%b %d, %Y",   # Nov 11, 2025
    "%m/%d/%Y",
    "%m/%d/%y",
]


def get_html(url: str) -> str:
    response = requests.get(url, headers=HEADERS, timeout=40)
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


def find_product_heading(soup: BeautifulSoup) -> Tag | None:
    for tag in soup.find_all(["h2", "h3", "h4"]):
        if tag.get_text(" ", strip=True).lower() == PRODUCT_NAME.lower():
            return tag
    return None


def find_photoshop_bulletin_urls(index_html: str) -> list[str]:
    soup = BeautifulSoup(index_html, "lxml")
    heading = find_product_heading(soup)

    urls = []

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
            urls.append(full_url)

    if not urls:
        for a in soup.find_all("a", href=True):
            text = a.get_text(" ", strip=True).lower()
            href = a["href"].lower()

            if (
                "photoshop" in text
                and "elements" not in text
                and "album" not in text
                and ("apsb" in text or "apsb" in href)
            ):
                urls.append(urljoin(INDEX_URL, a["href"]))

    return list(dict.fromkeys(urls))


def extract_date_from_bulletin_page(page_text: str) -> str:
    """
    Пытается найти дату публикации бюллетеня.
    У Adobe встречаются разные варианты:
    - Date Published
    - Originally posted
    - Last updated
    - просто дата на странице
    """
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
            match = DATE_RE.search(fragment)
            if match:
                return parse_date_to_iso(match.group(1))

    # fallback: первая дата на странице
    match = DATE_RE.search(page_text)
    if match:
        return parse_date_to_iso(match.group(1))

    raise ValueError("Дата публикации не найдена")


def parse_bulletin(url: str) -> list[dict]:
    html = get_html(url)
    soup = BeautifulSoup(html, "lxml")
    page_text = soup.get_text("\n", strip=True)

    cve_ids = sorted(set(cve.upper() for cve in CVE_RE.findall(page_text)))

    if not cve_ids:
        return []

    release_date = extract_date_from_bulletin_page(page_text)

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
    bulletin_urls = find_photoshop_bulletin_urls(index_html)

    print(f"Найдено бюллетеней Adobe Photoshop: {len(bulletin_urls)}")

    result = []

    for url in bulletin_urls:
        try:
            items = parse_bulletin(url)
            result.extend(items)
            print(f"[OK] {url} -> {len(items)} CVE")
            time.sleep(0.4)
        except Exception as e:
            print(f"[SKIP] {url}: {e}")

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

    print(f"Готово. CVE записано: {len(result)}")
    print(f"Файл: {OUT_FILE}")


if __name__ == "__main__":
    main()
