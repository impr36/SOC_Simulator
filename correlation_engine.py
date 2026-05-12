from datetime import datetime,timedelta
import pandas as pd

def correlate_alerts(alerts_df):

    incidents=[]

    if alerts_df.empty:
        return incidents

    alerts_df['timestamp']=pd.to_datetime(
        alerts_df['timestamp'],
        format='mixed',
        errors='coerce'
    )

    alerts_df=alerts_df.sort_values('timestamp')

    # =========================================================
    # BRUTE FORCE -> SUCCESSFUL LOGIN
    # =========================================================

    failed=alerts_df[
        alerts_df['type'].str.contains(
            "failed",
            case=False,
            na=False
        )
    ]

    success=alerts_df[
        alerts_df['type'].str.contains(
            "successful",
            case=False,
            na=False
        )
    ]

    if len(failed)>=5 and not success.empty:

        incidents.append({

            "timestamp":datetime.now().isoformat(),

            "type":"Possible Account Compromise",

            "severity":"CRITICAL",

            "description":
                "Multiple failed logins followed by successful authentication.",

            "explanation":
                "Potential brute-force attack succeeded.",

            "log_source":"Correlation Engine",

            "status":"New"
        })

    # =========================================================
    # POWERSHELL + LOLBIN
    # =========================================================

    powershell=alerts_df[
        alerts_df['type'].str.contains(
            "powershell",
            case=False,
            na=False
        )
    ]

    lolbin=alerts_df[
        alerts_df['type'].str.contains(
            "certutil|bitsadmin|mshta|regsvr32|rundll32",
            case=False,
            na=False,
            regex=True
        )
    ]

    if not powershell.empty and not lolbin.empty:

        incidents.append({

            "timestamp":datetime.now().isoformat(),

            "type":"Suspicious Scripted LOLBin Activity",

            "severity":"HIGH",

            "description":
                "PowerShell activity combined with LOLBin execution detected.",

            "explanation":
                "Possible malware staging or attacker execution chain.",

            "log_source":"Correlation Engine",

            "status":"New"
        })

    # =========================================================
    # RANSOMWARE BEHAVIOR
    # =========================================================

    ransomware=alerts_df[
        alerts_df['type'].str.contains(
            "ransomware|shadowcopy|encrypted",
            case=False,
            na=False
        )
    ]

    file_changes=alerts_df[
        alerts_df['type'].str.contains(
            "file modified|file deleted",
            case=False,
            na=False
        )
    ]

    if len(ransomware)>=1 and len(file_changes)>=5:

        incidents.append({

            "timestamp":datetime.now().isoformat(),

            "type":"Possible Ransomware Attack",

            "severity":"CRITICAL",

            "description":
                "Ransomware indicators combined with mass file modifications.",

            "explanation":
                "Potential encryption or destructive malware activity.",

            "log_source":"Correlation Engine",

            "status":"New"
        })

    # =========================================================
    # PERSISTENCE CHAIN
    # =========================================================

    persistence=alerts_df[
        alerts_df['type'].str.contains(
            "scheduled task|service|startup",
            case=False,
            na=False
        )
    ]

    if len(persistence)>=2:

        incidents.append({

            "timestamp":datetime.now().isoformat(),

            "type":"Persistence Mechanism Detected",

            "severity":"HIGH",

            "description":
                "Multiple persistence-related artifacts detected.",

            "explanation":
                "Possible attacker persistence established.",

            "log_source":"Correlation Engine",

            "status":"New"
        })

    return incidents