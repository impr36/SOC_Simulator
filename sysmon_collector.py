import win32evtlog
import pandas as pd
from datetime import datetime,timedelta

SYSMON_CHANNEL="Microsoft-Windows-Sysmon/Operational"

def read_sysmon_logs(start_time=None,hours=24):

    logs=[]

    try:

        if start_time:

            if isinstance(start_time,str):
                cutoff=datetime.fromisoformat(start_time)
            else:
                cutoff=start_time

        else:
            cutoff=datetime.now()-timedelta(hours=hours)

        query="*"

        handle=win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            win32evtlog.EvtQueryReverseDirection,
            query
        )
        max_events=80000
        processed=0
        while True:

            events=win32evtlog.EvtNext(
                handle,
                20
            )

            if not events:
                break

            for event in events:

                try:

                    xml=win32evtlog.EvtRender(
                        event,
                        win32evtlog.EvtRenderEventXml
                    )

                    if not xml:
                        continue

                    event_id=0

                    if "<EventID>" in xml:

                        event_id=int(
                            xml.split("<EventID>")[1]
                            .split("</EventID>")[0]
                        )

                    timestamp=""

                    if "SystemTime='" in xml:

                        timestamp=xml.split(
                            "SystemTime='"
                        )[1].split("'")[0]

                    event_time=datetime.fromisoformat(
                        timestamp.replace("Z","+00:00")
                    )

                    if event_time.replace(tzinfo=None)<cutoff:
                        continue

                    logs.append({

                        "timestamp":
                            event_time.isoformat(),

                        "event_id":
                            event_id,

                        "source":
                            "Sysmon",

                        "computer":
                            "",

                        "user":
                            "",

                        "process_name":
                            "",

                        "severity":
                            "INFO",

                        "description":
                            xml[:1500],

                        "raw_data":
                            xml
                    })
                    processed+=1

                    if processed>=max_events:
                        break
                except Exception as e:
                    print("Sysmon parse error:",e)

        df=pd.DataFrame(logs)

        print(f"Sysmon logs collected: {len(df)}")

        return df

    except Exception as e:

        print(f"Sysmon collection error: {e}")

        return pd.DataFrame()