import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import json, collections
from parsers import MasscanParser, NiktoParser, NmapJSONParser
for name, p, f in (("Masscan", MasscanParser, "data/vm/masscan.json"), ("Nikto", NiktoParser, "data/vm/nikto.json"), ("Nmap (C++ -> JSON)", NmapJSONParser, "data/vm/nmap_parsed.json")):
    fs = p.parse(f)
    print(f"{name:20s} находок: {len(fs):2d}  по серьёзности: {dict(collections.Counter(x['severity'] for x in fs))}")
print()
for x in NiktoParser.parse("data/vm/nikto.json")[:4]:
    print(x["severity"].ljust(7), x["cwe"], "|", x["description"][:80])
