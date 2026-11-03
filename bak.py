import json
for l in open("sonuc_dev.jsonl", encoding="utf-8"):
    r = json.loads(l)
    print("=====", r["cve"], "gerçek:", r["gercek"])
    for ad in ("norag", "rag_cwe", "rag_kod"):
        print(f"--- vuln_{ad}:", r[f"vuln_{ad}_ham"][:300].replace("\n", " | "))