import sys, re, json, os, chromadb, ollama

split, n = sys.argv[1], int(sys.argv[2])
db = chromadb.PersistentClient(path="vulndb")
cwe_col = db.get_collection("cwe")
kod_col = db.get_collection("cvefixes_kod")
CIKTI = f"sonuc_{split}.jsonl"

def sor(prompt):
    r = ollama.chat(model="qwen2.5-coder:7b",
                    messages=[{"role": "user", "content": prompt}],
                    options={"num_ctx": 8192, "temperature": 0})
    return r["message"]["content"]

def embed(t):
    return ollama.embed(model="nomic-embed-text", input=t)["embeddings"]

FORMAT = """Answer format (strict):
- If the code has no security weakness, answer exactly: NONE
- Otherwise one line per weakness: CWE-<number>: <short reason>
Report at most 3 weaknesses, and only ones actually present in the code."""

def ozetle(kod):
    return sor(f"""List the security weaknesses that are ACTUALLY PRESENT in this code, in English.
Only mention what you can see in the code. Do not guess about things that are not there.
One short sentence per weakness, no code. If there are none, say so.

{kod}""")

def cwe_baglam(ozet):
    h = cwe_col.query(query_embeddings=embed(ozet), n_results=6)
    return "\n---\n".join(d[:500] for d in h["documents"][0])

def ornek_baglam(kod):
    h = kod_col.query(query_embeddings=embed("search_document: " + kod), n_results=3)
    parcalar = []
    for d, m in zip(h["documents"][0], h["metadatas"][0]):
        parcalar.append(f"[Known vulnerable function, labeled {m['cwes']}]\n{d[:800]}")
    return "\n---\n".join(parcalar)

def norag(kod):
    return sor(f"Analyze this Python function for security weaknesses.\n{FORMAT}\n\n{kod}")

def rag_cwe(kod, ozet):
    return sor(f"""Reference weakness types (may or may not be relevant):
{cwe_baglam(ozet)}

Analyze this Python function for security weaknesses. Never mention a reference item that does not apply.
{FORMAT}

{kod}""")

def rag_kod(kod, ozet):
    return sor(f"""Similar known vulnerable functions from real CVEs (similar looking code does NOT guarantee the same weakness):
{ornek_baglam(kod)}

Reference weakness types (may or may not be relevant):
{cwe_baglam(ozet)}

Analyze this Python function for security weaknesses. Never mention a reference item that does not apply.
{FORMAT}

{kod}""")

def tahmin(cevap):
    return sorted({m.upper() for m in re.findall(r"^[^A-Za-z]*(CWE-\d+)", cevap, re.M | re.I)})

kayitlar = [k for k in json.load(open("eval_python.json", encoding="utf-8")) if k["split"] == split][:n]
bitenler = set()
if os.path.exists(CIKTI):
    bitenler = {json.loads(l)["id"] for l in open(CIKTI, encoding="utf-8")}

for i, k in enumerate(kayitlar, 1):
    if k["id"] in bitenler:
        continue
    s = {"id": k["id"], "cve": k["cve"], "gercek": k["cwes"]}
    for tur in ("vuln", "fixed"):
        kod = k[tur]
        ozet = ozetle(kod)
        for ad, cevap in (("norag", norag(kod)), ("rag_cwe", rag_cwe(kod, ozet)), ("rag_kod", rag_kod(kod, ozet))):
            s[f"{tur}_{ad}"] = tahmin(cevap)
            s[f"{tur}_{ad}_ham"] = cevap
    with open(CIKTI, "a", encoding="utf-8") as f:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"{i}/{len(kayitlar)} {k['cve']} gerçek={k['cwes']} norag={s['vuln_norag']} cwe={s['vuln_rag_cwe']} kod={s['vuln_rag_kod']}", flush=True)