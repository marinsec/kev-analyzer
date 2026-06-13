from datetime import date


def count_by_vendor(vulns: list[dict]) -> dict[str, int]:
    counts = {}
    for vuln in vulns:
        vendor = vuln["vendor"]
        counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def sort_on(item: tuple[str, int]) -> int:
    return item[1]


def counts_to_sorted_list(counts: dict[str, int]) -> list[tuple[str, int]]:
    result = []
    for key in counts:
        result.append((key, counts[key]))
    result = sorted(result, reverse=True, key=sort_on)
    return result


def count_by_year(vulns: list[dict]) -> dict[str, int]:
    counts = {}
    for vuln in vulns:
        year = vuln["date_added"][:4]
        counts[year] = counts.get(year, 0) + 1
    return counts


def search(vulns: list[dict], term: str) -> list[dict]:
    term = term.lower()
    results = []
    for vuln in vulns:
        haystack = f"{vuln['vendor']} {vuln['product']} {vuln['name']}".lower()
        if term in haystack:
            results.append(vuln)
    return results


def filter_ransomware(vulns: list[dict]) -> list[dict]:
    return [v for v in vulns if v.get("ransomware") == "Known"]


def filter_recent(vulns: list[dict], days: int) -> list[dict]:
    today = date.today()
    results = []
    for vuln in vulns:
        try:
            added = date.fromisoformat(vuln.get("date_added", ""))
        except ValueError:
            continue
        if (today - added).days <= days:
            results.append(vuln)
    return results


def load_inventory(path: str) -> list[str]:
    terms = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line.lower())
    return terms


def match_inventory(vulns: list[dict], terms: list[str]) -> list[dict]:
    results = []
    for vuln in vulns:
        haystack = f"{vuln['vendor']} {vuln['product']}".lower()
        for term in terms:
            if term in haystack:
                results.append(vuln)
                break
    return results
