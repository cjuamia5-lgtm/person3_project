import json

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def parse_detection_score(score_text):
   """
   Turn a string like '6/70' into numbers.
   Return malicious_votes, total_engines
   """
   try:
       left, right = score_text.split("/")
       return int(left), int(right)
   except Exception:
       return 0, 0


def calculate_score(person1_data, person2_data):
    score = 0
    reasons = []

    # -- -- -- -- -- -- -- -- -- --
    # Person 1 data
    # -- -- -- -- -- -- -- -- -- --
    suspicious = person1_data.get("suspicious_imports",{}
    total_hits = suspicious.get("total_hits", 0)
    categories = suspicious.get("categories_flagged", 0)
    matches = suspicious.get("matches", {})

    if total_hits >= 10:
       score += 20
       reasons.append("High number of suspicious imports found")

    elif total_hits >= 5:
        score +=10
        reasons.append("Moderate number of suspicious imports found")

    if categories >= 4:
       score += 20
       reasons.app("Many suspicious categories were flagged")

    elif categories >=2:
         score +=10
         reasons.append("Multiple suspicious categories were flagged")

    if "Privilege Escalation" in matches: 
