import sys, json, csv, re
from collections import defaultdict, Counter

sys.stdout.reconfigure(encoding="utf-8")

split = sys.argv[1] if len(sys.argv) > 1 else "test"
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


def basari(tahmin, gercek, k, mod):
    return any(t == g or (mod == "akraba" and akraba(t, g)) for t in tahmin[:k] for g in gercek)


rows = [json.loads(l) for l in open(f"sonuc_{split}.jsonl", encoding="utf-8") if l.strip()]
n = len(rows)
tum = json.load(open("eval_python.json", encoding="utf-8"))
kb = [k for k in tum if k["split"] == "kb"]
train = [k for k in tum if k["split"] == "train"]
sik = [c for c, _ in Counter(cw for k in kb for cw in k["cwes"]).most_common(3)]

print(f"Toplam CVEfixes: {len(tum)} fonksiyon (train={len(train)}, kb={len(kb)}, {split}={n})\n")
print(f"{'':16}{'Top1 tam':>10}{'Top3 tam':>10}{'Top1 akr.':>11}{'Top3 akr.':>11}")
for ad, anahtar in (("en sık 3 CWE", None), ("norag", "cwe_norag"), ("knn (np.dot)", "cwe_knn"), ("rag_kod", "cwe_rag_kod")):
    tah = [sik if anahtar is None else r[anahtar] for r in rows]
    v = [sum(basari(t, r["gercek"], k, m) for t, r in zip(tah, rows)) / n
         for k, m in ((1, "tam"), (3, "tam"), (1, "akraba"), (3, "akraba"))]
    print(f"{ad:16}" + "".join(f"{x:>{w}.0%}" for x, w in zip(v, (10, 10, 11, 11))))
