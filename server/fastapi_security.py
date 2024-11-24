import os

from fastapi import FastAPI
from fastapi import Request
from fastapi.openapi.utils import get_openapi
from fastapi.security import OAuth2

from common.security import APIToken
from server.auth import TokenManager
from server.exceptions import *


class TokenBearer(OAuth2):
    def __init__(self, token_manager: TokenManager):
        super().__init__()
        self.token_manager = token_manager

    async def __call__(self, request: Request):
        token = request.headers.get("Authorization")

        if token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header missing",
                headers={"WWW-Authenticate": "Bearer"}
            )

        if token.startswith("Bearer "):
            token = token[7:]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must start with 'Bearer '",
                headers={"WWW-Authenticate": "Bearer"}
            )
        try:
            body = await request.body()
            payload = self.token_manager.verify_token(
                token=token,
                method=request.method,
                url=str(request.url),
                body=body,
            )
        except APIToken.APITokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(type(e)),
                headers={"WWW-Authenticate": "Bearer"}
            )
        except ReplayAttackError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Replay attack detected",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except CodeInjectionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Code injection suspicion",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except:
            traceback.print_exc()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                headers={"WWW-Authenticate": "Bearer"}
            )
        return payload


def custom_openapi(app: FastAPI):
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=os.getenv("NAME"),
        version=os.getenv("VERSION"),
        description=os.getenv("DESCRIPTION"),
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "TokenAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"].values():
        for operation in path.values():
            if "security" in operation:
                operation["security"] = [{"TokenAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

oauth2_scheme = TokenBearer(TokenManager(os.getenv("SERVER_TOKENS_DB")))