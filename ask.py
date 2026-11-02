import sys, chromadb, ollama

col = chromadb.PersistentClient(path="vulndb").get_collection("cwe")
code = open(sys.argv[1], encoding="utf-8").read()

def sor(prompt):
    r = ollama.chat(model="qwen2.5-coder:7b",
                    messages=[{"role": "user", "content": prompt}],
                    options={"num_ctx": 8192, "temperature": 0})
    return r["message"]["content"]

# Adım 1: koddaki şüpheli noktaları İngilizce özetlet
ozet = sor(f"""List the security weaknesses that are ACTUALLY PRESENT in this code, in English.
Only mention what you can see in the code. Do not guess about things that are not there.
One short sentence per weakness, no code.

{code}""")
print("--- Arama için özet ---")
print(ozet, "\n")

# Adım 2: özetle veritabanında ara
q = ollama.embed(model="nomic-embed-text", input=ozet)["embeddings"]
hits = col.query(query_embeddings=q, n_results=6)
context = "\n---\n".join(hits["documents"][0])

# Adım 3: bulunanlarla nihai analiz
print("--- Analiz ---")
print(sor(f"""Bilinen zafiyet türleri (referans):
{context}

Aşağıdaki kodu incele. KURALLAR:
- Sadece kodda GERÇEKTEN var olan zafiyetleri yaz.
- Referanstaki bir zafiyet kodla ilgili değilse ASLA anma.
- Kodda zafiyet yoksa sadece tek cümle yaz: "Zafiyet bulunamadı." ve başka hiçbir şey yazma.
- Zafiyet varsa her biri için: CWE numarası, satır numarası, kısa düzeltme.
- Türkçe yaz. Çince karakter kullanma.

{code}"""))