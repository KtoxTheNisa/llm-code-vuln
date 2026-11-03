import sqlite3

c = sqlite3.connect(r"cvefixes\CVEfixes_v1.0.0\Data\CVEfixes.db")

print("=== Tablolar ===")
for (ad,) in c.execute("select name from sqlite_master where type='table'").fetchall():
    print(ad, c.execute(f"select count(*) from {ad}").fetchone()[0])

print("\n=== Fonksiyon sayısı: dil x before_change ===")
q = """
select f.programming_language, m.before_change, count(*)
from method_change m join file_change f on m.file_change_id = f.file_change_id
group by 1, 2 order by 3 desc limit 20
"""
for row in c.execute(q):
    print(row)

print("\n=== En sık CWE'ler (CVE sayısına göre) ===")
for row in c.execute("""
    select cwe_id, count(*) from cwe_classification
    group by cwe_id order by 2 desc limit 15
"""):
    print(row)