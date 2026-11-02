import os, subprocess


beklenen = {
    "sql.py": ["CWE-89"],
    "parola.py": ["CWE-798", "CWE-259", "CWE-321"],
    "komut.py": ["CWE-78", "CWE-77"],
    "yol.py": ["CWE-22", "CWE-23", "CWE-24", "CWE-25", "CWE-26", "CWE-27", "CWE-28", "CWE-29"],
    "pickle_ac.py": ["CWE-502"],
    "temiz.py": [],
}


for dosya, cwe in beklenen.items():
    sonuc = subprocess.run(
        ["python", "ask.py", os.path.join("testler", dosya)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    ).stdout
    analiz = sonuc.split("--- Analiz ---")[-1]
    if not cwe:
        bulundu = "bulunamadı" in analiz.lower() or "bulunmamaktadır" in analiz.lower()
    else:
        bulundu = any(c in analiz for c in cwe)
    print(f"{dosya:15} beklenen: {str(cwe)} -> {'DOĞRU' if bulundu else 'YANLIŞ'}")
    with open("sonuclar.txt", "a", encoding="utf-8") as f:
        f.write(f"===== {dosya} (beklenen {cwe}) =====\n{sonuc}\n\n")