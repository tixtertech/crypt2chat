from server.api.dependencies import *

router = APIRouter()

@router.post("/register")
@http_error_handler()
async def register(base_model: Register):
    return user_challenge.get_challenge(
        authentication_key=base_model.authentication_key.encode(),
        identity_key=base_model.identity_key.encode(),
        function=users_.register,
        args=[],
        kwargs={
            'username': base_model.username,
            'authentication_key': base_model.authentication_key.encode(),
            'identity_key': base_model.identity_key.encode(),
            'identity_sig': base_model.identity_sig.encode(),
            'override': False
        }
    )

@router.post("/register/verify")
@http_error_handler({
    user_challenge.AccessForbiddenError: status.HTTP_403_FORBIDDEN,
    user_challenge.BadRequestError: status.HTTP_400_BAD_REQUEST
})
async def verify(base_model: Verify):
    return user_challenge.verify_challenge(
        authenticated_challenge=base_model.authChallenge,
    )

@router.get("/token")
@http_error_handler()
async def token(token: dict = Depends(oauth2_scheme)):
    return token