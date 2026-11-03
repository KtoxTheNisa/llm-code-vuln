import json, chromadb, ollama

EMB_MODEL = "nomic-embed-text"
db = chromadb.PersistentClient(path="vulndb")

for ad in ("cvefixes", "cvefixes_kod", "cwe"):
    try:
        db.delete_collection(ad)
    except Exception:
        pass

col = db.get_or_create_collection("cvefixes")
kayitlar = [k for k in json.load(open("eval_python.json", encoding="utf-8")) if k["split"] == "kb"]
print("kb kümesi:", len(kayitlar))

for i in range(0, len(kayitlar), 16):
    b = kayitlar[i:i + 16]
    docs = [k["vuln"][:3500] for k in b]
    embs = ollama.embed(model=EMB_MODEL, input=docs)["embeddings"]
    col.upsert(
        ids=["cvf-" + k["id"] for k in b],
        documents=docs,
        embeddings=embs,
        metadatas=[{
            "cve": k["cve"],
            "cwes": ", ".join(k["cwes"]),
            "cwe_names": k.get("cwe_names", ", ".join(k["cwes"])),
            "fixed": (k.get("fixed") or "")[:2000]
        } for k in b]
    )
    print(f"{min(i + 16, len(kayitlar))}/{len(kayitlar)} yüklendi", flush=True)

print("Toplam kayıt:", col.count())
