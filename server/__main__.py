import os

from dotenv import load_dotenv

load_dotenv()

import uvicorn
import time
from fastapi import FastAPI, Response, Request
from fastapi.responses import FileResponse

from server.keys.routes import router as keys_router
from server.admin.routes import router as admin_router
from server.auth.routes import router as auth_router
from server.fastapi_security import custom_openapi
from server.logging import logging_, requests_
from server.messaging.routes import router as messaging_router
from server.users.routes import router as accounts_router
from datetime import datetime, timezone, UTC

logging_.info('server starting...')
app = FastAPI()
app.openapi = lambda: custom_openapi(app)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    try:
        response = await call_next(request)
        stop_time = time.time()
        requests_.log_request(
            request=datetime.fromtimestamp(start_time, tz=UTC),
            response=datetime.fromtimestamp(stop_time, tz=UTC),
            runtime=(stop_time - start_time)*1000,
            method=request.method,
            url=str(request.url),
            host=request.client.host,
            port=request.client.port,
            response_code=response.status_code,
        )
        return response
    except:
        stop_time = time.time()
        requests_.log_request(
            request=datetime.fromtimestamp(start_time, tz=UTC),
            response=datetime.fromtimestamp(stop_time, tz=UTC),
            runtime=(stop_time - start_time)*1000,
            method=request.method,
            url=str(request.url),
            host=request.client.host,
            port=request.client.port,
            response_code=500,
        )
        raise

@app.get("/ping")
def ping():
    return Response(status_code=int(os.getenv("SERVER_STATUS")), content=os.getenv("SERVER_STATUS_MESSAGE"))

if not int(os.getenv("SERVER_STATUS")) == 503:
    @app.get("/")
    def getting_started():
        return FileResponse(path="server/static/index.html")

    # Include routers
    app.include_router(admin_router, prefix="/admin", tags=["admin"])
    app.include_router(keys_router, prefix="/keys", tags=["keys"])
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(accounts_router, prefix="/users", tags=["users"])
    app.include_router(messaging_router, prefix="/messaging", tags=["messaging"])

else:
    @app.get("/")
    def getting_started():
        return FileResponse(path="server/static/unavailable.html")

uvicorn.run(
    app,
    host=os.getenv("SERVER_HOST"),
    port=int(os.getenv("SERVER_PORT")),
    ssl_keyfile=os.getenv("SERVER_RSA_PRV"),
    ssl_keyfile_password=os.getenv("SERVER_PASSWORD"),
    ssl_certfile=os.getenv("SERVER_CERT")
    )