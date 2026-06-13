def parse_vulnerabilities(data: dict) -> list[dict]:
    parsed = []
    for vuln in data["vulnerabilities"]:
        entry = {
            "cve": vuln.get("cveID", ""),
            "vendor": vuln.get("vendorProject", ""),
            "product": vuln.get("product", ""),
            "name": vuln.get("vulnerabilityName", ""),
            "date_added": vuln.get("dateAdded", ""),
            "description": vuln.get("shortDescription", ""),
            "due_date": vuln.get("dueDate", ""),
            "required_action": vuln.get("requiredAction", ""),
            "ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
        }
        parsed.append(entry)
    return parsed
