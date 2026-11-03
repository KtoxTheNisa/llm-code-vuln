import gzip, os, sqlite3, time

KAYNAK = r"cvefixes\CVEfixes_v1.0.0\Data\CVEfixes-2021-06-09.sql.gz"
HEDEF = r"cvefixes\CVEfixes_v1.0.0\Data\CVEfixes.db"

if os.path.exists(HEDEF):
    os.remove(HEDEF)  # yarım kalmış denemeyi temizle

con = sqlite3.connect(HEDEF, isolation_level=None)  # transaction'ı dökümün kendisi yönetiyor
tampon, sayac, t0 = [], 0, time.time()

with gzip.open(KAYNAK, "rt", encoding="utf-8", errors="replace") as f:
    for satir in f:
        tampon.append(satir)
        # Sadece ';' ile biten satırlarda ifade bitti mi diye bak (kodlar çok satırlı olabiliyor)
        if satir.rstrip().endswith(";"):
            ifade = "".join(tampon)
            if sqlite3.complete_statement(ifade):
                con.execute(ifade)
                tampon = []
                sayac += 1
                if sayac % 20000 == 0:
                    print(f"{sayac} ifade, {int(time.time()-t0)} sn", flush=True)

con.commit()
con.close()
print("Bitti:", sayac, "ifade,", int(time.time() - t0), "sn")