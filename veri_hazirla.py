import sqlite3
import json
import csv
import random

# CVEfixes veritabanina baglan
db_yolu = "../ragprojeKopya/cvefixes/CVEfixes_v1.0.0/Data/CVEfixes.db"
baglanti = sqlite3.connect(db_yolu)
imlec = baglanti.cursor()

# 1000.csv dosyasindan CWE isimlerini oku
cwe_isimleri = {}
dosya = open("1000.csv", "r", encoding="utf-8-sig")
okuyucu = csv.DictReader(dosya)
for satir in okuyucu:
    kod = "CWE-" + satir["CWE-ID"]
    cwe_isimleri[kod] = satir["Name"]
dosya.close()

# Hangi commit hangi CVE'ye ait
commit_cve = {}
for cve_id, h in imlec.execute("SELECT cve_id, hash FROM fixes"):
    commit_cve[h] = cve_id

# Hangi CVE hangi CWE hatasina ait
cve_cwe = {}
for cve_id, cwe_id in imlec.execute("SELECT cve_id, cwe_id FROM cwe_classification"):
    if cwe_id and cwe_id.startswith("CWE-"):
        cve_cwe[cve_id] = cwe_id

# Python'daki hatali (before_change = True) fonksiyonlari cek
sorgu = """
SELECT m.method_change_id, m.file_change_id, m.name, m.code, f.hash, f.filename
FROM method_change m
JOIN file_change f ON m.file_change_id = f.file_change_id
WHERE f.programming_language = 'Python' AND m.before_change = 'True'
"""

kayitlar = []
eklenen_kodlar = []

for mid, fid, fonksiyon_adi, kod, h, dosya_adi in imlec.execute(sorgu):
    if h not in commit_cve:
        continue
    cve = commit_cve[h]
    if cve not in cve_cwe:
        continue
    cwe = cve_cwe[cve]

    if kod is None or kod.strip() == "":
        continue

    # Ayni kod daha once eklendiyse tekrar ekleme
    kisa_kod = kod.strip()
    if kisa_kod in eklenen_kodlar:
        continue
    eklenen_kodlar.append(kisa_kod)

    cwe_adi = cwe_isimleri.get(cwe, "")
    kayitlar.append({
        "id": str(mid) + ":" + str(fid) + ":" + fonksiyon_adi,
        "name": fonksiyon_adi,
        "filename": dosya_adi,
        "cve": cve,
        "cwes": [cwe],
        "cwe_names": cwe + " (" + cwe_adi + ")",
        "vuln": kod
    })

# Veriyi karistir ve train / kb (RAG) / test olarak ayir
random.seed(42)
random.shuffle(kayitlar)

toplam = len(kayitlar)
kb_sinir = int(toplam * 0.50)      # %50 RAG veritabani icin
train_sinir = int(toplam * 0.90)   # %40 model egitimi (train) icin, kalan %10 test icin

for i in range(toplam):
    if i < kb_sinir:
        kayitlar[i]["split"] = "kb"
    elif i < train_sinir:
        kayitlar[i]["split"] = "train"
    else:
        kayitlar[i]["split"] = "test"

cikti = open("eval_python.json", "w", encoding="utf-8")
json.dump(kayitlar, cikti, ensure_ascii=False, indent=2)
cikti.close()

train_sayisi = 0
kb_sayisi = 0
test_sayisi = 0
for k in kayitlar:
    if k["split"] == "train":
        train_sayisi += 1
    elif k["split"] == "kb":
        kb_sayisi += 1
    elif k["split"] == "test":
        test_sayisi += 1

print("Toplam Python fonksiyonu:", toplam)
print("Train (egitim) seti:", train_sayisi)
print("KB (RAG veritabani) seti:", kb_sayisi)
print("Test seti:", test_sayisi)
