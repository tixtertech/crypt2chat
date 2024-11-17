from os.path import join

CACHE_DIR = "./cache/admin"

def pubkey(name):
    return join(CACHE_DIR, f"{name}_pubkey.pem")
def privkey(name):
    return join(CACHE_DIR, f"{name}_privkey.pem")
def cert(name):
    return join(CACHE_DIR, f"{name}_cert.pem")
