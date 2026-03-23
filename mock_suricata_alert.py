import json
import time
from datetime import datetime

alert = {
    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
    "event_type": "alert",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "alert": {
        "signature": "ET EXPLOIT Possible CVE-2023-XXXXX Detected in Traffic"
    }
}

with open("eve.json", "a", encoding="utf-8") as f:
    f.write(json.dumps(alert) + "\n")
print(f"[{datetime.now().strftime('%H:%M:%S')}] Mock alert appended to eve.json!")
