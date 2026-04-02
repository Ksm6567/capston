import sys
import time
import traceback
from yara_scanner import YaraScanner

log_file = open('test_output.txt', 'w', encoding='utf-8')

def my_callback(msg):
    log_file.write(f"CALLBACK: {msg}\n")
    log_file.flush()

try:
    target_dir = r"C:\Users\ybi65\OneDrive\Desktop\capstone"
    rules_file = r"C:\Users\ybi65\OneDrive\Desktop\capstone\backend\rules\enhanced_rules.yar"

    scanner = YaraScanner(rules_file, target_dir, my_callback)
    scanner.start()

    time.sleep(3)
    scanner.stop()
except Exception as e:
    log_file.write(traceback.format_exc())
    log_file.flush()
