import csv, re, chromadb, ollama

col = chromadb.PersistentClient(path="vulndb").get_or_create_collection("cwe")
rows = list(csv.DictReader(open("1000.csv", encoding="utf-8-sig")))

def clean(metin):
    return re.sub(r"::+", " | ", metin or "").strip(" |")

docs, ids, metas = [], [], []
for r in rows:
    if not r["Description"]:
        continue
    doc = (
        f"CWE-{r['CWE-ID']}: {r['Name']}\n"
        f"Açıklama: {r['Description']}\n"
        f"Detay: {r['Extended Description']}\n"
        f"Önlemler: {clean(r['Potential Mitigations'])[:600]}"
    )
    docs.append(doc)
    ids.append(f"cwe-{r['CWE-ID']}")
    metas.append({"cwe": f"CWE-{r['CWE-ID']}", "name": r["Name"],
                  "abstraction": r["Weakness Abstraction"]})

for i in range(0, len(docs), 25):
    embs = ollama.embed(model="nomic-embed-text", input=docs[i:i+25])["embeddings"]
    col.upsert(ids=ids[i:i+25], documents=docs[i:i+25],
               embeddings=embs, metadatas=metas[i:i+25])
    print(f"{min(i+25, len(docs))}/{len(docs)} yüklendi")

print("Toplam kayıt:", col.count())