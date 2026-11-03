import sys, re, json, os, chromadb, ollama

split, n = sys.argv[1], int(sys.argv[2])
db = chromadb.PersistentClient(path="vulndb")
cwe_col = db.get_collection("cwe")
kod_col = db.get_collection("cvefixes_kod")
CIKTI = f"sonuc2_{split}.jsonl"

def sor(prompt, max_tok=300):
    r = ollama.chat(model="qwen2.5-coder:7b",
                    messages=[{"role": "user", "content": prompt}],
                    options={"num_ctx": 8192, "temperature": 0, "num_predict": max_tok})
    return r["message"]["content"]

def embed(t):
    return ollama.embed(model="nomic-embed-text", input=t)["embeddings"]

def ornekler(kod):
    h = kod_col.query(
        query_embeddings=embed("search_query: " + kod),
        n_results=3
    )
    
def cwe_tanim(metin):
    h = cwe_col.query(query_embeddings=embed(metin), n_results=6)
    return "\n---\n".join(d[:500] for d in h["documents"][0])

TOP3 = "Give your 3 best guesses for the CWE, most likely first, one per line as CWE-<number>. Output only those 3 lines."
SKOR = ("Rate how likely this Python function contains a security vulnerability. "
        "Answer with one integer from 0 (certainly safe) to 10 (certainly vulnerable). Output only the number.")

def ozet(kod):
    return sor("This Python function contains a security weakness. In 2 short English sentences, describe the most likely "
               f"type of weakness (e.g. injection, path traversal, missing authentication, improper input validation). No code.\n\n{kod}", 120)

def cwe_norag(kod):
    return sor(f"This Python function contains a security weakness.\n{TOP3}\n\n{kod}", 60)

def cwe_rag_cwe(kod, oz):
    return sor(f"Reference weakness types:\n{cwe_tanim(oz)}\n\nThis Python function contains a security weakness.\n{TOP3}\n\n{kod}", 60)

def cwe_rag_kod(kod, oz):
    return sor(f"Similar known vulnerable functions from real CVEs (similar code does not guarantee the same weakness):\n{ornekler(kod)}\n\n"
               f"Reference weakness types:\n{cwe_tanim(oz)}\n\nThis Python function contains a security weakness.\n{TOP3}\n\n{kod}", 60)

def sayi(c):
    m = re.search(r"\d+", c)
    return min(int(m.group()), 10) if m else None

def skor(kod):
    return sayi(sor(f"{SKOR}\n\n{kod}", 5))

def skor_rag(kod):
    return sayi(sor(f"Known vulnerable functions from real CVEs, for reference:\n{ornekler(kod)}\n\n{SKOR}\n\n{kod}", 5))

def cwe_liste(c):
    g = []
    for x in re.findall(r"CWE-\d+", c, re.I):
        if x.upper() not in g:
            g.append(x.upper())
    return g[:3]

kayitlar = [k for k in json.load(open("eval_python.json", encoding="utf-8")) if k["split"] == split][:n]
bitenler = set()
if os.path.exists(CIKTI):
    bitenler = {json.loads(l)["id"] for l in open(CIKTI, encoding="utf-8")}

for i, k in enumerate(kayitlar, 1):
    if k["id"] in bitenler:
        continue
    oz = ozet(k["vuln"])
    s = {"id": k["id"], "cve": k["cve"], "gercek": k["cwes"], "ozet": oz,
         "cwe_norag": cwe_liste(cwe_norag(k["vuln"])),
         "cwe_rag_cwe": cwe_liste(cwe_rag_cwe(k["vuln"], oz)),
         "cwe_rag_kod": cwe_liste(cwe_rag_kod(k["vuln"], oz)),
         "vuln_skor": skor(k["vuln"]), "fixed_skor": skor(k["fixed"]),
         "vuln_skor_rag": skor_rag(k["vuln"]), "fixed_skor_rag": skor_rag(k["fixed"])}
    with open(CIKTI, "a", encoding="utf-8") as f:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"{i}/{len(kayitlar)} {k['cve']} gerçek={k['cwes']} norag={s['cwe_norag']} kod={s['cwe_rag_kod']} "
          f"skor v/f={s['vuln_skor']}/{s['fixed_skor']}", flush=True)