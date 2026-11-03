import sys, json, csv, re
from collections import defaultdict

split = sys.argv[1]
parents = defaultdict(set)
for r in csv.DictReader(open("1000.csv", encoding="utf-8-sig")):
    for p in re.findall(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000", r["Related Weaknesses"] or ""):
        parents["CWE-" + r["CWE-ID"]].add("CWE-" + p)

def atalar(c, derinlik=2):
    sonuc, simdi = set(), {c}
    for _ in range(derinlik):
        simdi = {p for x in simdi for p in parents.get(x, ())}
        sonuc |= simdi
    return sonuc

def akraba(a, b):
    return a == b or b in atalar(a) or a in atalar(b)

rows = [json.loads(l) for l in open(f"sonuc_{split}.jsonl", encoding="utf-8")]
n = len(rows)
print(f"{split}: {n} çift\n")
print(f"{'':10}{'Tespit':>8}{'Tam CWE':>9}{'Akraba':>8}{'Yanlış alarm':>14}")
for ad in ("norag", "rag_cwe", "rag_kod"):
    tespit = sum(bool(r[f"vuln_{ad}"]) for r in rows)
    tam = sum(bool(set(r[f"vuln_{ad}"]) & set(r["gercek"])) for r in rows)
    akr = sum(any(akraba(t, g) for t in r[f"vuln_{ad}"] for g in r["gercek"]) for r in rows)
    alarm = sum(bool(r[f"fixed_{ad}"]) for r in rows)
    print(f"{ad:10}{tespit/n:>8.0%}{tam/n:>9.0%}{akr/n:>8.0%}{alarm/n:>14.0%}")