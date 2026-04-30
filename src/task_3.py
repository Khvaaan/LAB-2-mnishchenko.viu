import json
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring


INPUT_FILE = "result_task_2.json"
OUT_FILE = "result_task_3.xml"


FIRST_LEVEL_FIELDS = [
    "ID",
    "vendor_release_date",
    "vendor_release_url",
    "url",
    "published_date",
    "updated_date",
    "description",
]


def add_text_element(parent: Element, tag: str, value) -> None:
    element = SubElement(parent, tag)
    element.text = "" if value is None else str(value)


def build_xml(data: list[dict]) -> Element:
    root = Element("vulnerabilities")

    for item in data:
        vuln_el = SubElement(root, "vulnerability")

        for field in FIRST_LEVEL_FIELDS:
            add_text_element(vuln_el, field, item.get(field, ""))

        cvss_list_el = SubElement(vuln_el, "cvss_list")
        for cvss in item.get("cvss_list", []):
            cvss_el = SubElement(
                cvss_list_el,
                "cvss",
                {
                    "version": str(cvss.get("version", "")),
                    "score": str(cvss.get("score", "")),
                    "severity": str(cvss.get("severity", "")),
                },
            )
            cvss_el.text = str(cvss.get("vector", ""))

        cpe_list_el = SubElement(vuln_el, "cpe_list")
        for cpe in item.get("cpe_list", []):
            add_text_element(cpe_list_el, "cpe", cpe)

        cwe_list_el = SubElement(vuln_el, "cwe_list")
        for cwe_id, cwe_data in item.get("cwe", {}).items():
            cwe_el = SubElement(
                cwe_list_el,
                "cwe",
                {
                    "id": str(cwe_id),
                    "name": str(cwe_data.get("name", "")),
                },
            )
            cwe_el.text = str(cwe_data.get("description", ""))

    return root


def prettify_xml(root: Element) -> str:
    raw_xml = tostring(root, encoding="utf-8")
    parsed = minidom.parseString(raw_xml)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    root = build_xml(data)
    xml_text = prettify_xml(root)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(xml_text)

    print(f"Готово. Записей: {len(data)}")
    print(f"Файл: {OUT_FILE}")


if __name__ == "__main__":
    main()
