import json


def load_json_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------------
# Score Person 1 (file analysis)
# -----------------------------
def score_person1_data(p1):
    score = 0
    reasons = []

    suspicious = p1.get("suspicious_imports", {})
    total_hits = suspicious.get("total_hits", 0)
    categories_flagged = suspicious.get("categories_flagged", 0)
    matches = suspicious.get("matches", {})

    # Score by number of hits
    if total_hits >= 15:
        score += 25
        reasons.append("High number of suspicious indicators (+25)")
    elif total_hits >= 8:
        score += 15
        reasons.append("Moderate number of suspicious indicators (+15)")
    elif total_hits >= 3:
        score += 8
        reasons.append("Low number of suspicious indicators (+8)")

    # Score by categories
    if categories_flagged >= 5:
        score += 20
        reasons.append("Many suspicious categories flagged (+20)")
    elif categories_flagged >= 3:
        score += 10
        reasons.append("Several suspicious categories flagged (+10)")
    elif categories_flagged >= 1:
        score += 5
        reasons.append("At least one suspicious category flagged (+5)")

    # High-risk categories
    high_risk_categories = {
        "Network": 10,
        "Shell Execution": 15,
        "Persistence": 15,
        "Privilege Escalation": 20,
        "Obfuscation / Injection": 20,
        "Crypto / Ransomware": 25
    }

    for category, points in high_risk_categories.items():
        if category in matches and matches[category]:
            score += points
            reasons.append(f"{category} indicators found (+{points})")

    return score, reasons


# -----------------------------
# Score Person 2 (threat intel)
# -----------------------------
def score_person2_data(p2):
    score = 0
    reasons = []

    malicious_votes = p2.get("malicious_votes", 0)
    suspicious_votes = p2.get("suspicious_votes", 0)
    malware_family = p2.get("malware_family")
    tags = p2.get("tags", [])

    # VirusTotal scoring
    if malicious_votes >= 15:
        score += 50
        reasons.append("Very high VirusTotal malicious votes (+50)")
    elif malicious_votes >= 8:
        score += 35
        reasons.append("High VirusTotal malicious votes (+35)")
    elif malicious_votes >= 3:
        score += 20
        reasons.append("Moderate VirusTotal malicious votes (+20)")
    elif malicious_votes >= 1:
        score += 10
        reasons.append("Low VirusTotal malicious votes (+10)")

    if suspicious_votes >= 3:
        score += 10
        reasons.append("Several VirusTotal suspicious votes (+10)")
    elif suspicious_votes >= 1:
        score += 5
        reasons.append("Some VirusTotal suspicious votes (+5)")

    # Malware family
    if malware_family:
        score += 20
        reasons.append(f"Malware family identified: {malware_family} (+20)")

    # Dangerous tags
    dangerous_tags = {
        "ransomware": 25,
        "stealer": 20,
        "trojan": 15,
        "backdoor": 20,
        "botnet": 20,
        "worm": 15,
        "loader": 12,
        "dropper": 12
    }

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in dangerous_tags:
            points = dangerous_tags[tag_lower]
            score += points
            reasons.append(f"Dangerous tag found: {tag_lower} (+{points})")

    return score, reasons


# -----------------------------
# Reduce false positives
# -----------------------------
def reduce_false_positives(score, p1, p2):
    reasons = []

    suspicious = p1.get("suspicious_imports", {})
    total_hits = suspicious.get("total_hits", 0)
    categories_flagged = suspicious.get("categories_flagged", 0)

    malicious_votes = p2.get("malicious_votes", 0)
    suspicious_votes = p2.get("suspicious_votes", 0)
    malware_family = p2.get("malware_family")
    tags = p2.get("tags", [])

    # Weak evidence filter
    if malicious_votes == 0 and suspicious_votes == 0 and total_hits <= 2:
        score -= 15
        reasons.append("Low evidence and no VirusTotal detections (-15)")

    # Few categories
    if categories_flagged <= 1 and not malware_family:
        score -= 10
        reasons.append("Very few categories and no malware family (-10)")

    # No tags + no detections
    if malicious_votes == 0 and len(tags) == 0:
        score -= 10
        reasons.append("No malicious votes and no threat tags (-10)")

    if score < 0:
        score = 0

    return score, reasons


# -----------------------------
# Final verdict
# -----------------------------
def get_verdict(score):
    if score >= 80:
        return "Malicious"
    elif score >= 45:
        return "Suspicious"
    elif score >= 15:
        return "Likely Safe"
    else:
        return "Safe"


# -----------------------------
# Main function
# -----------------------------
def build_final_scoring_report():
    p1 = load_json_file("person1_output.json")
    p2 = load_json_file("person2_output.json")

    final_score = 0
    reasons = []

    p1_score, p1_reasons = score_person1_data(p1)
    final_score += p1_score
    reasons.extend(p1_reasons)

    p2_score, p2_reasons = score_person2_data(p2)
    final_score += p2_score
    reasons.extend(p2_reasons)

    final_score, filter_reasons = reduce_false_positives(final_score, p1, p2)
    reasons.extend(filter_reasons)

    verdict = get_verdict(final_score)

    report = {
        "filename": p1.get("filename", "unknown"),
        "sha256": p1.get("hashes", {}).get("SHA256", p2.get("sha256", "unknown")),
        "final_score": final_score,
        "verdict": verdict,
        "person1_summary": {
            "total_hits": p1.get("suspicious_imports", {}).get("total_hits", 0),
            "categories_flagged": p1.get("suspicious_imports", {}).get("categories_flagged", 0)
        },
        "person2_summary": {
            "malicious_votes": p2.get("malicious_votes", 0),
            "suspicious_votes": p2.get("suspicious_votes", 0),
            "malware_family": p2.get("malware_family"),
            "tags": p2.get("tags", [])
        },
        "reasons": reasons
    }

    return report


# -----------------------------
# Run script
# -----------------------------
if __name__ == "__main__":
    report = build_final_scoring_report()
    print(json.dumps(report, indent=4))

    # Save output to file
    with open("judge_output.json", "w") as f:
        json.dump(report, f, indent=4)
