import sys, json, csv, re
from collections import defaultdict, Counter

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

def basari(tahmin, gercek, k, mod):
    return any(t == g or (mod == "akraba" and akraba(t, g)) for t in tahmin[:k] for g in gercek)

rows = [json.loads(l) for l in open(f"sonuc2_{split}.jsonl", encoding="utf-8")]
n = len(rows)
kb = [k for k in json.load(open("eval_python.json", encoding="utf-8")) if k["split"] == "kb"]
sik = [c for c, _ in Counter(cw for k in kb for cw in k["cwes"]).most_common(3)]

print(f"{split}: {n} çift\n")
print("A) CWE tanıma (zafiyetli fonksiyon verildiğinde)")
print(f"{'':16}{'Top1 tam':>10}{'Top3 tam':>10}{'Top1 akr.':>11}{'Top3 akr.':>11}")
for ad, anahtar in (("en sık 3 CWE", None), ("norag", "cwe_norag"), ("rag_cwe", "cwe_rag_cwe"), ("rag_kod", "cwe_rag_kod")):
    tah = [sik if anahtar is None else r[anahtar] for r in rows]
    v = [sum(basari(t, r["gercek"], k, m) for t, r in zip(tah, rows)) / n
         for k, m in ((1, "tam"), (3, "tam"), (1, "akraba"), (3, "akraba"))]
    print(f"{ad:16}" + "".join(f"{x:>{w}.0%}" for x, w in zip(v, (10, 10, 11, 11))))

print("\nB) Zafiyetli ve düzeltilmiş hâli ayırt etme (rastgele = %50)")
for ad in ("skor", "skor_rag"):
    p = []
    for r in rows:
        v, f = r[f"vuln_{ad}"], r[f"fixed_{ad}"]
        if v is None or f is None:
            continue
        p.append(1 if v > f else 0.5 if v == f else 0)
    ort_v = sum(r[f"vuln_{ad}"] or 0 for r in rows) / n
    ort_f = sum(r[f"fixed_{ad}"] or 0 for r in rows) / n
    print(f"{ad:10} doğru sıralama: {sum(p)/len(p):.0%}  (ort. puan zafiyetli {ort_v:.1f}, düzeltilmiş {ort_f:.1f})")