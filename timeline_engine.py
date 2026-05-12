import pandas as pd

def build_attack_timeline(alerts_df):

    timeline=[]

    if alerts_df.empty:
        return timeline

    alerts_df['timestamp']=pd.to_datetime(
        alerts_df['timestamp'],
        format='mixed',
        errors='coerce'
    )

    alerts_df=alerts_df.sort_values(
        by='timestamp'
    )

    for _,row in alerts_df.iterrows():

        entry={

            "timestamp":
                row.get("timestamp"),

            "event":
                row.get("type","Unknown"),

            "severity":
                row.get("severity","LOW"),

            "description":
                row.get("description",""),

            "source":
                row.get("log_source","Unknown")
        }

        timeline.append(entry)

    return timeline

def detect_attack_progression(alerts_df):

    attack_chain=[]

    if alerts_df.empty:
        return attack_chain

    alert_types=" ".join(
        alerts_df['type'].astype(str).tolist()
    ).lower()

    # =====================================================
    # INITIAL ACCESS
    # =====================================================

    if "failed login" in alert_types \
    or "brute force" in alert_types:

        attack_chain.append(
            "Initial Access"
        )

    # =====================================================
    # EXECUTION
    # =====================================================

    if "powershell" in alert_types \
    or "cmd" in alert_types \
    or "script" in alert_types:

        attack_chain.append(
            "Execution"
        )

    # =====================================================
    # PERSISTENCE
    # =====================================================

    if "scheduled task" in alert_types \
    or "service" in alert_types \
    or "startup" in alert_types:

        attack_chain.append(
            "Persistence"
        )

    # =====================================================
    # DEFENSE EVASION
    # =====================================================

    if "defender" in alert_types \
    or "log cleared" in alert_types:

        attack_chain.append(
            "Defense Evasion"
        )

    # =====================================================
    # CREDENTIAL ACCESS
    # =====================================================

    if "mimikatz" in alert_types \
    or "credential" in alert_types \
    or "lsass" in alert_types:

        attack_chain.append(
            "Credential Access"
        )

    # =====================================================
    # IMPACT
    # =====================================================

    if "ransomware" in alert_types \
    or "encrypted" in alert_types:

        attack_chain.append(
            "Impact"
        )

    return list(set(attack_chain))