from server.api.dependencies import *

router = APIRouter()

@router.get("/cert")
@http_error_handler()
async def get_cert():
    with open(conf("keys", "cert"), "rb") as f:
        cert = f.read()
    return JSONResponse(cert.decode())

@router.get("/rsa")
@http_error_handler()
async def get_rsa_pubkey():
    with open(conf("keys", "rsa_pub"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())

@router.get("/ed448")
@http_error_handler()
async def get_ed448_pubkey():
    with open(conf("keys", "ed448_pub"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())

@router.get("/x448")
@http_error_handler()
async def get_x448_pubkey():
    with open(conf("keys", "ed448_prv"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())