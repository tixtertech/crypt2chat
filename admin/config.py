from os.path import join

CACHE_DIR = "./cache/admin"

def pubkey(name):
    return join(CACHE_DIR, f"{name}_pub.pem")
def privkey(name):
    return join(CACHE_DIR, f"{name}_prv.pem")
def cert(name):
    return join(CACHE_DIR, f"{name}_cert.pem")
