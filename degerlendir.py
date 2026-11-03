import sys, re, json, os, csv
from collections import defaultdict
import numpy as np
import chromadb, ollama

sys.stdout.reconfigure(encoding="utf-8")

split = sys.argv[1] if len(sys.argv) > 1 else "test"
tum = json.load(open("eval_python.json", encoding="utf-8"))
kayitlar = [k for k in tum if k["split"] == split]
if len(sys.argv) > 2:
    kayitlar = kayitlar[:int(sys.argv[2])]
CIKTI = f"sonuc_{split}.jsonl"

cwe_aciklama = {}
for r in csv.DictReader(open("1000.csv", encoding="utf-8-sig")):
    cwe_aciklama["CWE-" + r["CWE-ID"]] = f"{r['Name']}: {r['Description'][:180]}"

col = chromadb.PersistentClient(path="vulndb").get_collection("cvefixes")
veri = col.get(include=["embeddings", "documents", "metadatas"])
M = np.array(veri["embeddings"], dtype=np.float32)
M /= np.linalg.norm(M, axis=1, keepdims=True)


def sor(prompt, max_tok=60):
    r = ollama.chat(model="qwen2.5-coder:7b", messages=[{"role": "user", "content": prompt}],
                    options={"num_ctx": 8192, "temperature": 0, "num_predict": max_tok})
    return r["message"]["content"]


def embed(t):
    v = np.array(ollama.embed(model="nomic-embed-text", input=t[:3500])["embeddings"][0], dtype=np.float32)
    return v / np.linalg.norm(v)


def ornekler(kod):
    q = embed(kod)
    skor = np.dot(M, q)
    sirali = np.argsort(skor)[::-1]

    # 1) Saf kNN (sadece vektör uzaklığı, farklı CVE'lerden ağırlıksız ilk 3 komşu)
    knn, gorulen_cve = [], set()
    for idx in sirali[1:]:
        m = veri["metadatas"][idx]
        if m["cve"] in gorulen_cve:
            continue
        gorulen_cve.add(m["cve"])
        for cw in m["cwes"].split(","):
            cw = cw.strip()
            if cw and cw not in knn:
                knn.append(cw)
        if len(knn) >= 3:
            break

    # 2) RAG + LLM için en yakın 3 örnek + CWE tanımları
    oy = defaultdict(float)
    for r_i, idx in enumerate(sirali[:5]):
        ag = (float(max(skor[idx], 0.0)) ** 2) / (r_i + 1)
        for cw in veri["metadatas"][idx]["cwes"].split(","):
            cw = cw.strip()
            if cw:
                oy[cw] += ag
    adaylar = [c for c, _ in sorted(oy.items(), key=lambda x: x[1], reverse=True)[:4]]

    parcalar = []
    for idx in sirali[:3]:
        m = veri["metadatas"][idx]
        parcalar.append(f"[{m['cve']} | {m.get('cwe_names', m['cwes'])} | np.dot={skor[idx]:.3f}]\n{veri['documents'][idx][:600]}")

    tanimlar = "\n".join(f"- {c}: {cwe_aciklama.get(c, '')}" for c in adaylar if c in cwe_aciklama)
    return "\n---\n".join(parcalar), tanimlar, knn[:3], adaylar[:3]


TOP3 = "Give your 3 best guesses for the CWE, most likely first, one per line as CWE-<number>. Output only those 3 lines."


def cwe_norag(kod):
    return sor(f"This Python function contains a security weakness.\n{TOP3}\n\n{kod[:2500]}")


def cwe_rag_kod(kod, ctx, tanimlar, adaylar):
    return sor(f"Top 3 similar vulnerable functions from vector DB (np.dot):\n{ctx}\n\n"
               f"Candidate CWE definitions:\n{tanimlar}\n\n"
               f"Analyze the Python function below using the similar examples above (primary candidate: {adaylar[0]}).\n{TOP3}\n\n{kod[:2500]}")


def cwe_liste(c, yedek=None):
    g = []
    for x in re.findall(r"CWE-\d+", c, re.I):
        if x.upper() not in g:
            g.append(x.upper())
    if yedek:
        for y in yedek:
            if y not in g:
                g.append(y)
    return g[:3]


bitenler = set()
if os.path.exists(CIKTI):
    bitenler = {json.loads(l)["id"] for l in open(CIKTI, encoding="utf-8") if l.strip()}

for i, k in enumerate(kayitlar, 1):
    if k["id"] in bitenler:
        continue
    ctx, tanimlar, knn, adaylar = ornekler(k["vuln"])
    s = {
        "id": k["id"],
        "cve": k["cve"],
        "gercek": k["cwes"],
        "cwe_knn": knn,
        "cwe_norag": cwe_liste(cwe_norag(k["vuln"])),
        "cwe_rag_kod": cwe_liste(cwe_rag_kod(k["vuln"], ctx, tanimlar, adaylar), adaylar)
    }
    with open(CIKTI, "a", encoding="utf-8") as f:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"{i}/{len(kayitlar)} {k['cve']} gerçek={k['cwes']} norag={s['cwe_norag']} knn={s['cwe_knn']} rag_kod={s['cwe_rag_kod']}", flush=True)
