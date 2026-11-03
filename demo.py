import sys, json, re
import numpy as np
import chromadb, ollama

sys.stdout.reconfigure(encoding="utf-8")

EMB_MODEL = "nomic-embed-text"
LLM = "qwen2.5-coder:7b"
TOP_K = 3

col = chromadb.PersistentClient(path="vulndb").get_collection("cvefixes")
veri = col.get(include=["embeddings", "documents", "metadatas"])
M = np.array(veri["embeddings"], dtype=np.float32)
M /= np.linalg.norm(M, axis=1, keepdims=True)


def sor(prompt, max_tok=100):
    r = ollama.chat(model=LLM, messages=[{"role": "user", "content": prompt}],
                    options={"num_ctx": 8192, "temperature": 0, "repeat_penalty": 1.15, "num_predict": max_tok})
    return re.sub(r"[\u4e00-\u9fff]+", "", r["message"]["content"])


def embed(text):
    v = np.array(ollama.embed(model=EMB_MODEL, input=text[:3500])["embeddings"][0], dtype=np.float32)
    return v / np.linalg.norm(v)


def cwe_liste(c, yedek):
    g = []
    for x in re.findall(r"CWE-\d+", c, re.I):
        if x.upper() not in g:
            g.append(x.upper())
    for y in yedek:
        if y not in g:
            g.append(y)
    return g[:3]


tum = json.load(open("eval_python.json", encoding="utf-8"))
train = [k for k in tum if k["split"] == "train"]
kb = [k for k in tum if k["split"] == "kb"]
test = [k for k in tum if k["split"] == "test"]

n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else len(test)
test = test[:n]

print(f"CVEfixes toplam: {len(tum)} fonksiyon (train={len(train)}, rag_kb={len(kb)}, test={len(test)})")
print(f"vulndb vektör sayısı: {col.count()} ({M.shape[1]} boyut)\n")

top1, top3, say = 0, 0, 0
try:
    for i, k in enumerate(test, 1):
        kod = k["vuln"]
        gercek = k["cwes"]

        q = embed(kod)
        skor = np.dot(M, q)
        sirali = np.argsort(skor)[::-1]
        en_yakin = sirali[:TOP_K]

        oy = {}
        for r_i, idx in enumerate(sirali[:5]):
            ag = (float(max(skor[idx], 0.0)) ** 2) / (r_i + 1)
            for cw in veri["metadatas"][idx]["cwes"].split(","):
                cw = cw.strip()
                if cw:
                    oy[cw] = oy.get(cw, 0.0) + ag
        adaylar = [c for c, _ in sorted(oy.items(), key=lambda x: x[1], reverse=True)[:3]]

        ornekler = []
        for idx in en_yakin:
            m = veri["metadatas"][idx]
            ornekler.append(f"[{m['cve']} | {m['cwes']} | benzerlik={skor[idx]:.3f}]\n{veri['documents'][idx][:550]}")

        prompt = f"""Benzer zafiyetli kod örnekleri (np.dot ile bulundu, en yakın CWE: {', '.join(adaylar)}):
{chr(10).join(ornekler)}

Aşağıdaki Python fonksiyonunu incele.
- İlk satıra en olası 3 CWE numarasını yaz (benzer örneklerle aynı hataysa {adaylar[0]} ile başla).
- İkinci satıra 1 cümle Türkçe açıklama yaz.

{kod[:2200]}"""

        cevap = sor(prompt, 90).strip()
        tahmin = cwe_liste(cevap, adaylar)

        t1 = any(t == g for t in tahmin[:1] for g in gercek)
        t3 = any(t == g for t in tahmin[:3] for g in gercek)
        top1 += int(t1)
        top3 += int(t3)
        say += 1

        durum = "DOĞRU" if t1 else ("DOĞRU (Top3)" if t3 else "YANLIŞ")
        satirlar = [s.strip() for s in cevap.splitlines() if s.strip()]
        aciklama = satirlar[-1] if satirlar else cevap

        print(f"--- [{i}/{len(test)}] {k['cve']} | {k['name']} ({k['filename']}) | gerçek={gercek} ---")
        for j in en_yakin:
            m = veri["metadatas"][j]
            print(f"  np.dot={skor[j]:.3f}  {m['cve']}  {m['cwes']}")
        print(f"  tahmin={tahmin} -> {durum}  (başarı: Top1={top1}/{say} %{top1*100/say:.0f}, Top3={top3}/{say} %{top3*100/say:.0f})")
        print(f"  analiz: {aciklama[:130]}\n", flush=True)
except KeyboardInterrupt:
    print("\nDurduruldu.")

if say:
    print(f"Sonuç ({say} fonksiyon): Top1 = {top1}/{say} ({top1/say:.0%}), Top3 = {top3}/{say} ({top3/say:.0%})")
