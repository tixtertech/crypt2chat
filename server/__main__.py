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
from server.logging import logging_
from server.messaging.routes import router as messaging_router
from server.users.routes import router as accounts_router

logging_.app_info('server starting...')
app = FastAPI()
app.openapi = lambda: custom_openapi(app)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log the incoming request details
    start_time = time.time()
    logging_.middleware_info(f"Incoming request: {request.method} {request.url} from {request.client.host}")

    # Process the request and get the response
    try:
        response = await call_next(request)

        # Log the response details
        process_time = time.time() - start_time
        if response.status_code >= 500:
            logging_.middleware_error(
                f"Error: Status {response.status_code}"
            )
        logging_.middleware_info(
            f"Response: {response.status_code} for {request.method} {request.url} "
            f"from {request.client.host} in {process_time:.2f}s"
        )
        return response
    except Exception as e:
        # Log the error
        process_time = time.time() - start_time
        logging_.middleware_error(
            f"Error: {e}"
        )
        logging_.middleware_info(
            f"Response: 500 for {request.method} {request.url} "
            f"from {request.client.host} in {process_time:.2f}s"
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