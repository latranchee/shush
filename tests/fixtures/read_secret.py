import base64
import os
import sys


encoded = os.environ.get("SHUSH_E2E_SECRET")
if not encoded:
    print("SHUSH_E2E_SECRET is missing", file=sys.stderr)
    sys.exit(2)

decoded = base64.b64decode(encoded).decode("utf-8")
print(f"py_decoded={decoded}")

