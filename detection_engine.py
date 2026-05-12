from datetime import datetime
from rules import KEYWORD_RULES
from rules import RULES


def determine_category(rule):

    name = rule["name"].lower()

    if "login" in name or "rdp" in name:
        return "Authentication"

    elif "privilege" in name:
        return "Privilege Escalation"

    elif "powershell" in name or "execution" in name:
        return "Execution"

    elif "credential" in name or "mimikatz" in name:
        return "Credential Access"

    elif "ransomware" in name:
        return "Ransomware"

    elif "scan" in name:
        return "Network Scanning"

    elif "tamper" in name:
        return "System Tampering"

    elif "defender" in name:
        return "Defense Evasion"

    return "Other"

# ====================== DETECTION ENGINE ======================

def detect_advanced_threats(df):

    alerts=[]

    if df.empty:
        return alerts

    for _,row in df.iterrows():

        try:

            combined_text=" ".join([

                str(row.get("description","")),
                str(row.get("process_name","")),
                str(row.get("source","")),
                str(row.get("raw_data",""))

            ]).lower()

            for rule_id,rule in KEYWORD_RULES.items():

                matched_keyword=None

                for keyword in rule["keywords"]:

                    if keyword.lower() in combined_text:

                        matched_keyword=keyword
                        break

                if matched_keyword:

                    alerts.append({

                        "timestamp":row.get(
                            "timestamp",
                            datetime.now().isoformat()
                        ),

                        "event_id":rule_id,

                        "type":rule["name"],

                        "severity":rule["severity"],

                        "description":rule["name"],

                        "category": determine_category(rule["name"]),

                        "explanation":
                            f"Matched keyword: {matched_keyword}",

                        "matched_keyword":matched_keyword,

                        "raw_log":combined_text[:1000],

                        "log_source":"HIDS",

                        "status":"New"
                    })

        except Exception as e:
            print("Advanced detection error:",e)

    return alerts