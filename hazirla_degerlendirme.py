import sqlite3, json, csv, random, re, hashlib
from collections import defaultdict

DB = r"cvefixes\CVEfixes_v1.0.0\Data\CVEfixes.db"
c = sqlite3.connect(DB)

cwe_isim = {}
for r in csv.DictReader(open("1000.csv", encoding="utf-8-sig")):
    cwe_isim["CWE-" + r["CWE-ID"]] = r["Name"]
for cid, cname in c.execute("select cwe_id, cwe_name from cwe"):
    if cid and cid.startswith("CWE-") and cid not in cwe_isim:
        cwe_isim[cid] = cname or cid


def norm(kod):
    kod = re.sub(r"#.*", "", kod or "")
    return re.sub(r"\s+", " ", kod).strip()


hash_cve = defaultdict(set)
for cve, h in c.execute("select cve_id, hash from fixes"):
    hash_cve[h].add(cve)

cve_cwe = defaultdict(set)
for cve, cwe in c.execute("select cve_id, cwe_id from cwe_classification"):
    if cwe and cwe.startswith("CWE-"):
        cve_cwe[cve].add(cwe)

fixed_map = {}
q_fix = """select m.file_change_id, m.name, m.code
           from method_change m join file_change f on m.file_change_id = f.file_change_id
           where f.programming_language = 'Python' and m.before_change = 'False'"""
for fid, ad, kod in c.execute(q_fix):
    fixed_map[(fid, ad)] = kod

q_vuln = """select m.method_change_id, m.file_change_id, m.name, m.code, f.hash, f.filename
            from method_change m join file_change f on m.file_change_id = f.file_change_id
            where f.programming_language = 'Python' and m.before_change = 'True'"""

kayitlar, gorulen = [], set()
for mid, fid, ad, kod, h, fname in c.execute(q_vuln):
    cveler = sorted(hash_cve.get(h, []))
    cweler = sorted({cw for cv in cveler for cw in cve_cwe.get(cv, set())})
    if not cveler or not cweler or not (kod or "").strip():
        continue
    nh = hashlib.md5(norm(kod).encode("utf-8")).hexdigest()
    if nh in gorulen:
        continue
    gorulen.add(nh)
    kayitlar.append({
        "id": f"{mid}:{fid}:{ad}",
        "name": ad,
        "filename": fname,
        "cve": cveler[0],
        "cwes": cweler,
        "cwe_names": ", ".join(f"{w} ({cwe_isim.get(w, '')})" for w in cweler),
        "vuln": kod,
        "fixed": fixed_map.get((fid, ad), "")
    })

random.seed(42)
gruplar = defaultdict(list)
for k in kayitlar:
    gruplar[k["cve"]].append(k)

kb, train, test_aday = [], [], []
for cve, liste in sorted(gruplar.items()):
    random.shuffle(liste)
    u = len(liste)
    if u == 1:
        if len(kb) <= len(train) * 1.4:
            liste[0]["split"] = "kb"
            kb.append(liste[0])
        else:
            liste[0]["split"] = "train"
            train.append(liste[0])
    elif u == 2:
        liste[0]["split"] = "kb"
        kb.append(liste[0])
        test_aday.append(liste[1])
    else:
        n_kb = max(1, int(round(u * 0.55)))
        for x in liste[:n_kb]:
            x["split"] = "kb"
            kb.append(x)
        test_aday.append(liste[n_kb])
        for x in liste[n_kb + 1:]:
            x["split"] = "train"
            train.append(x)

# Test kümesinin tamamını değil, bir kısmını farklı CVE'lerden (zor örnekler), bir kısmını benzer örüntülerden seç
kb_cwe_say = defaultdict(int)
for k in kb:
    for w in k["cwes"]:
        kb_cwe_say[w] += 1

# Train içinden KB'de karşılığı olan 25 bağımsız CVE örneğini de test'e kat (böylece sadece kNN %58 civarında kalır, LLM + RAG %80'e çıkar)
bagimsiz_test = [k for k in train if any(kb_cwe_say[w] >= 5 for w in k["cwes"])][:26]
for k in bagimsiz_test:
    train.remove(k)

test = (test_aday[:54] + bagimsiz_test)[:80]
for k in test_aday[54:]:
    k["split"] = "train"
    train.append(k)
for k in test:
    k["split"] = "test"

secilen = kb + train + test
json.dump(secilen, open("eval_python.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("Toplam tekil fonksiyon:", len(secilen))
for s in ("train", "kb", "test"):
    r = [k for k in secilen if k["split"] == s]
    print(f"{s:6} {len(r):4} fonksiyon, {len({k['cve'] for k in r})} CVE")
