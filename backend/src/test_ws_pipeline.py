import asyncio
import websockets
import json
import requests
import time

async def test_pipeline():
    try:
        # Stop Yara if running
        requests.post("http://127.0.0.1:8000/api/yara/stop")
        time.sleep(1)
        
        async with websockets.connect("ws://127.0.0.1:8000/ws/logs") as ws:
            # Start Yara
            res = requests.post("http://127.0.0.1:8000/api/yara/start")
            print("Start Response:", res.json())
            
            # Create a malicious file
            with open(r"C:\Users\ybi65\OneDrive\Desktop\capstone\backend\test_live_malware.txt", "w") as f:
                f.write("HACKER_DETECTED")
                
            # Wait for messages
            for _ in range(10):
                msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                data = json.loads(msg)
                print("WS received:", data)
                if "HACKER_DETECTED" in data.get("message", "") or "test_live_malware.txt" in data.get("message", ""):
                    print("SUCCESS! Detected.")
                    return
            print("FAILED to detect in WS.")
    except Exception as e:
        print("Error:", e)
    finally:
        requests.post("http://127.0.0.1:8000/api/yara/stop")

asyncio.run(test_pipeline())
