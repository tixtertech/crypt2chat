import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from server.exceptions import *

router = APIRouter()

@router.get("/cert")
@http_error_handler()
async def get_pubkey():
    with open(os.getenv("SERVER_CERT"), "rb") as f:
        cert = f.read()
    return JSONResponse(cert.decode())

@router.get("/rsa")
@http_error_handler()
async def get_pubkey():
    with open(os.getenv("SERVER_RSA_PUB"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())

@router.get("/x448")
@http_error_handler()
async def get_pubkey():
    with open(os.getenv("SERVER_X448_PUB"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())

@router.get("/ed448")
@http_error_handler()
async def get_pubkey():
    with open(os.getenv("SERVER_ED448_PUB"), "rb") as f:
        pubbkey = f.read()
    return JSONResponse(pubbkey.decode())