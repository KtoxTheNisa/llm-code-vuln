import json
import numpy as np
import chromadb
import ollama

# JSON dosyasini oku
dosya = open("eval_python.json", "r", encoding="utf-8")
tum_veriler = json.load(dosya)
dosya.close()

# Sadece RAG (kb) icin ayrilan ornekleri al
kb_verileri = []
for k in tum_veriler:
    if k["split"] == "kb":
        kb_verileri.append(k)

print("RAG icin vektorlestirilecek fonksiyon sayisi:", len(kb_verileri))

# ChromaDB vektor veritabanini olustur
istemci = chromadb.PersistentClient(path="vulndb")
try:
    istemci.delete_collection("cvefixes")
except:
    pass

koleksiyon = istemci.create_collection("cvefixes")

sayac = 0
for k in kb_verileri:
    kod = k["vuln"][:3500]

    # Hazir embed modeli ile kodu vektorlestir
    sonuc = ollama.embed(model="nomic-embed-text", input=kod)
    vektor = np.array(sonuc["embeddings"][0], dtype=np.float32)

    # np.dot ile benzerlik bulabilmek icin vektoru normalize et
    uzunluk = np.linalg.norm(vektor)
    if uzunluk > 0:
        vektor = vektor / uzunluk

    koleksiyon.add(
        ids=[k["id"]],
        documents=[kod],
        embeddings=[vektor.tolist()],
        metadatas=[{
            "cve": k["cve"],
            "cwes": ",".join(k["cwes"]),
            "cwe_names": k.get("cwe_names", ""),
            "filename": k["filename"],
            "name": k["name"]
        }]
    )

    sayac = sayac + 1
    if sayac % 50 == 0 or sayac == len(kb_verileri):
        print(sayac, "/", len(kb_verileri), "vektor veritabanina kaydedildi")

print("Bitti! Toplam kayit:", koleksiyon.count())
