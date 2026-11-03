import json, chromadb, ollama

col = chromadb.PersistentClient(path="vulndb").get_or_create_collection("cvefixes_kod")
kb = {k["id"]: k for k in json.load(open("eval_python.json", encoding="utf-8")) if k["split"] == "kb"}
kb = list(kb.values())

for i in range(0, len(kb), 10):
    b = kb[i:i+10]
    embs = ollama.embed(model="nomic-embed-text",
                        input=["search_document: " + k["vuln"] for k in b])["embeddings"]
    col.upsert(ids=[k["id"] for k in b], documents=[k["vuln"] for k in b],
               embeddings=embs,
               metadatas=[{"cve": k["cve"], "cwes": ",".join(k["cwes"])} for k in b])
    print(f"{min(i+10, len(kb))}/{len(kb)}", flush=True)
print("Toplam kayıt:", col.count())