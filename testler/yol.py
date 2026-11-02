def dosya_oku(dosya_adi):
    with open("/var/data/" + dosya_adi) as f:
        return f.read()