import sqlite3, json, csv, random
from collections import defaultdict, Counter

DB = r"cvefixes\CVEfixes_v1.0.0\Data\CVEfixes.db"
c = sqlite3.connect(DB)
kb_cwe = {"CWE-" + r["CWE-ID"] for r in csv.DictReader(open("1000.csv", encoding="utf-8-sig"))}

hash_cve = defaultdict(set)
for cve, h in c.execute("select cve_id, hash from fixes"):
    hash_cve[h].add(cve)
cve_cwe = defaultdict(set)
for cve, cwe in c.execute("select cve_id, cwe_id from cwe_classification"):
    if cwe in kb_cwe:                      # bilgisiz ve RAG'de olmayan etiketleri at
        cve_cwe[cve].add(cwe)

gruplar = defaultdict(dict)
q = """select m.file_change_id, m.name, m.code, m.before_change, f.hash
       from method_change m join file_change f on m.file_change_id = f.file_change_id
       where f.programming_language = 'Python'"""
for fid, ad, kod, once, h in c.execute(q):
    gruplar[(fid, ad, h)]["vuln" if once == "True" else "fixed"] = kod

kayitlar = []
for (fid, ad, h), d in gruplar.items():
    if "vuln" not in d or "fixed" not in d or d["vuln"] == d["fixed"]:
        continue
    if not (80 <= len(d["vuln"]) <= 3000):
        continue
    cveler = sorted(hash_cve.get(h, []))
    cwe = set()
    for cv in cveler:
        cwe |= cve_cwe.get(cv, set())
    if cveler and cwe:
        kayitlar.append({"id": f"{fid}:{ad}", "cve": cveler[0], "cwes": sorted(cwe),
                         "vuln": d["vuln"], "fixed": d["fixed"]})

# CVE bazında üçe böl: kb (bilgi tabanına girecek), dev (ayar), test (son ölçüm)
cveler = sorted({k["cve"] for k in kayitlar})
random.seed(42)
random.shuffle(cveler)
n = len(cveler)
bolum = {}
for i, cv in enumerate(cveler):
    bolum[cv] = "kb" if i < n * 0.4 else ("dev" if i < n * 0.6 else "test")

random.shuffle(kayitlar)
sayac, secilen = Counter(), []
for k in kayitlar:
    k["split"] = bolum[k["cve"]]
    sinir = 99 if k["split"] == "kb" else 2   # kb: sınırsız, dev/test: CVE başına 2
    if sayac[k["cve"]] < sinir:
        sayac[k["cve"]] += 1
        secilen.append(k)

json.dump(secilen, open("eval_python.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("Toplam:", len(secilen), "çift,", n, "CVE")
for s in ("kb", "dev", "test"):
    r = [k for k in secilen if k["split"] == s]
    print(f"{s:5} {len(r):4} çift, {len({k['cve'] for k in r})} CVE")
for cw, m in Counter(cw for k in secilen for cw in k["cwes"]).most_common(10):
    print(f"  {cw:10} {m}")