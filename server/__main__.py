import time
from datetime import datetime, UTC

import uvicorn
from fastapi import FastAPI, Response, Request
from fastapi.responses import FileResponse

from server.api.routes import *
from server.core import *

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

@app.get("/status")
def status():
    return Response(status_code=int(conf("network", "status")), content=conf("network", "status_msg"))

if not int(conf("network", "status")) == 503:
    @app.get("/")
    def getting_started():
        return FileResponse(path="server/api/static/index.html")

    # Include routers
    app.include_router(admin_router, prefix="/admin", tags=["admin"])
    app.include_router(keys_router, prefix="/keys", tags=["keys"])
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(users_router, prefix="/users", tags=["users"])
    app.include_router(messages_router, prefix="/messages", tags=["messages"])
    app.include_router(conversations_router, prefix="/conversations", tags=["conversations"])

else:
    @app.get("/")
    def getting_started():
        return FileResponse(path="server/api/static/unavailable.html")

uvicorn.run(
    app,
    host=conf("network", "host"),
    port=int(conf("network", "port")),
    ssl_keyfile=conf("keys", "rsa_prv"),
    ssl_keyfile_password=conf("secrets", "password"),
    ssl_certfile=conf("keys", "cert")
    )