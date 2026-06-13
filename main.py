import json
import argparse

from fetch import download_kev, load_kev
from parse import parse_vulnerabilities
from analyze import (
    count_by_vendor,
    counts_to_sorted_list,
    count_by_year,
    search,
    filter_ransomware,
    filter_recent,
    load_inventory,
    match_inventory,
)


def banner():
    print(r"""
 _  _________     __     _    _   _    _    _  __   ____________ ____
| |/ / ____\ \   / /    / \  | \ | |  / \  | | \ \ / /__  / ____|  _ \
| ' /|  _|  \ \ / /    / _ \ |  \| | / _ \ | |  \ V /  / /|  _| | |_) |
| . \| |___  \ V /    / ___ \| |\  |/ ___ \| |___| |  / /_| |___|  _ 
|_|\_\_____|  \_/    /_/   \_\_| \_/_/   \_\_____|_| /____|_____|_| \_\
""")


def get_data(force_update: bool) -> dict:
    if force_update:
        print("Updating KEV catalog from CISA...\n")
        return download_kev()
    try:
        return load_kev()
    except FileNotFoundError:
        print("No local catalog found, downloading...\n")
        return download_kev()


def print_vulns(vulns: list[dict]) -> None:
    for v in vulns:
        flag = "  [RANSOMWARE]" if v.get("ransomware") == "Known" else ""
        print(f"{v['cve']} | {v['vendor']} {v['product']} ({v['date_added']}){flag}")
        print(f"  {v['name']}")
        if v.get("due_date"):
            print(f"  Remediation due: {v['due_date']}")
        print()
    print(f"Total: {len(vulns)} matching entries")


def print_stats(vulns: list[dict]) -> None:
    print(f"Loaded {len(vulns)} known exploited vulnerabilities")
    print(f"Linked to ransomware campaigns: {len(filter_ransomware(vulns))}\n")

    print("=== Top 10 vendors by KEV count ===")
    for vendor, count in counts_to_sorted_list(count_by_vendor(vulns))[:10]:
        print(f"{count:4}  {vendor}")

    print("\n=== KEV entries added per year ===")
    for year, count in sorted(count_by_year(vulns).items()):
        print(f"{year}: {count}")


def stats_dict(vulns: list[dict]) -> dict:
    return {
        "total": len(vulns),
        "ransomware_linked": len(filter_ransomware(vulns)),
        "top_vendors": counts_to_sorted_list(count_by_vendor(vulns))[:10],
        "by_year": dict(sorted(count_by_year(vulns).items())),
    }


def main():
    parser = argparse.ArgumentParser(description="CISA KEV catalog analyzer")
    parser.add_argument("--update", action="store_true",
                        help="refresh the catalog from CISA before running")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="output as JSON")
    parser.add_argument("--search", metavar="TERM",
                        help="filter by vendor, product, or vulnerability name")
    parser.add_argument("--ransomware", action="store_true",
                        help="only entries linked to ransomware campaigns")
    parser.add_argument("--recent", type=int, metavar="DAYS",
                        help="only entries added in the last N days")
    parser.add_argument("--inventory", metavar="FILE",
                        help="match entries against a file of products/vendors")
    args = parser.parse_args()

    if not args.as_json:
        banner()

    data = get_data(args.update)
    vulns = parse_vulnerabilities(data)

    subset = vulns
    filtered = False

    if args.search:
        subset = search(subset, args.search)
        filtered = True
    if args.inventory:
        try:
            terms = load_inventory(args.inventory)
        except FileNotFoundError:
            print(f"Inventory file not found: {args.inventory}")
            return
        subset = match_inventory(subset, terms)
        filtered = True
    if args.ransomware:
        subset = filter_ransomware(subset)
        filtered = True
    if args.recent is not None:
        subset = filter_recent(subset, args.recent)
        filtered = True

    if filtered:
        if args.as_json:
            print(json.dumps(subset, indent=2))
        else:
            print_vulns(subset)
    else:
        if args.as_json:
            print(json.dumps(stats_dict(vulns), indent=2))
        else:
            print_stats(vulns)


if __name__ == "__main__":
    main()
