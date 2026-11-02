import chromadb, ollama

col = chromadb.PersistentClient(path="vulndb").get_collection("cwe")
soru = "user input concatenated into SQL query"
q = ollama.embed(model="nomic-embed-text", input=soru)["embeddings"]
sonuc = col.query(query_embeddings=q, n_results=3)
for doc in sonuc["documents"][0]:
    print(doc[:200], "\n---")