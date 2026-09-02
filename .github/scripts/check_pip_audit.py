import json
import sys

try:
    with open("pip-audit.json") as f:
        data = json.load(f)
except Exception:
    data = {}

# pip-audit --format json emits {"dependencies": [...]}. Older/alternate
# formats emit a bare list. Support both.
if isinstance(data, dict):
    dependencies = data.get("dependencies", [])
else:
    dependencies = data

vulns = [v for v in dependencies if v.get("vulns")]
if vulns:
    print(f"FAIL: {len(vulns)} packages with known vulnerabilities")
    for v in vulns:
        for vuln in v["vulns"]:
            print(f'  {v["name"]}=={v["version"]}: {vuln["id"]}')
    sys.exit(1)
print("PASS: No known vulnerabilities in dependencies")
