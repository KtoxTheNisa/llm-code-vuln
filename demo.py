import sys
import json
import numpy as np
import chromadb
import ollama

sys.stdout.reconfigure(encoding="utf-8")

# 1. Veri setini oku ve sayilari goster
dosya = open("eval_python.json", "r", encoding="utf-8")
veriler = json.load(dosya)
dosya.close()

train_listesi = []
kb_listesi = []
test_listesi = []

for k in veriler:
    if k["split"] == "train":
        train_listesi.append(k)
    elif k["split"] == "kb":
        kb_listesi.append(k)
    elif k["split"] == "test":
        test_listesi.append(k)

print("=== VERI SETI BILGILERI ===")
print("Train (Model Egitim Seti):", len(train_listesi), "fonksiyon")
print("RAG Bilgi Tabani (KB)    :", len(kb_listesi), "fonksiyon")
print("Test Seti                :", len(test_listesi), "fonksiyon")

# 2. ChromaDB'deki RAG vektorlerini yukle
istemci = chromadb.PersistentClient(path="vulndb")
koleksiyon = istemci.get_collection("cvefixes")
db_kayitlari = koleksiyon.get(include=["embeddings", "documents", "metadatas"])

db_vektorler = db_kayitlari["embeddings"]
db_kodlar = db_kayitlari["documents"]
db_bilgiler = db_kayitlari["metadatas"]

print("Vektor Veritabanindaki Kayit Sayisi:", len(db_vektorler))
print("===========================\n")

# Kac tane test ornegi calistirilacak (varsayilan 5, ya da terminalden girilen sayi)
adet = 5
if len(sys.argv) > 1:
    adet = int(sys.argv[1])

for sira in range(adet):
    ornek = test_listesi[sira]
    kullanici_kodu = ornek["vuln"]
    gercek_cwe = ornek["cwes"]

    # 3. Kullanicinin kodunu embed modeli ile vektorlestir
    emb_sonuc = ollama.embed(model="nomic-embed-text", input=kullanici_kodu[:3500])
    kod_vektoru = np.array(emb_sonuc["embeddings"][0], dtype=np.float32)
    kod_vektoru = kod_vektoru / np.linalg.norm(kod_vektoru)

    # 4. np.dot kullanarak veritabanindaki orneklerle kiyasla
    skorlar = []
    for i in range(len(db_vektorler)):
        db_vektor = np.array(db_vektorler[i], dtype=np.float32)
        db_vektor = db_vektor / np.linalg.norm(db_vektor)

        benzerlik = float(np.dot(db_vektor, kod_vektoru))
        skorlar.append((benzerlik, i))

    # En yuksek benzerlikten en dusuge sirala ve en yakin 3 ornegi al
    skorlar.sort(reverse=True)
    en_yakin_3 = skorlar[:3]

    print("--------------------------------------------------")
    print(f"Ornek {sira + 1} | Fonksiyon: {ornek['name']} ({ornek['cve']}) | Gercek Hata: {gercek_cwe}")
    print("Vektor DB'den np.dot ile bulunan en yakin 3 ornek:")

    rag_metni = ""
    for b_skor, idx in en_yakin_3:
        bilgi = db_bilgiler[idx]
        ornek_kod = db_kodlar[idx][:500]
        print(f"  -> {bilgi['cve']} | {bilgi['cwes']} | np.dot skoru: {b_skor:.3f}")

        rag_metni += f"Ornek ({bilgi['cve']} - {bilgi['cwes']}):\n{ornek_kod}\n\n"

    # 5. En yakin 3 ornegi prompt icinde ek olarak LLM'e ver
    prompt = f"""Asagida vektor veritabanindan bulunan en benzer 3 hatali kod ornegi verilmistir:

{rag_metni}
Simdi kullanicinin yazdigi su Python kodundaki guvenlik hatasini bul.
Hangi CWE hatasi oldugunu yaz ve 1-2 cumle ile Turkce acikla:

{kullanici_kodu[:2000]}"""

    cevap = ollama.chat(
        model="qwen2.5-coder:7b",
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0, "num_predict": 120}
    )

    print("\nModelin Cevabi:")
    print(cevap["message"]["content"].strip())
    print()
