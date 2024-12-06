import requests
from common.diffie_helman import *
from common.security import *

API_URL = os.getenv("API_URL")
ssl_verification = False if os.getenv("VERIFY_CERT") == "false" else True

def raise_for_status(response: requests.Response, expected_status_code=200):
    if response.status_code != expected_status_code:
        raise ValueError(
            f"Unexpected status code: {response.status_code} for url: {response.url}\nResponse content: {response.text}"
        )

class Token:
    def __init__(self, user_id: str, diffie_helman: DiffieHelman):
        self.user_id = user_id
        response = requests.get(f"{API_URL}/keys/x448", verify=ssl_verification)
        response.raise_for_status()
        server_ik = response.json().encode()
        self.api_token = APIToken(
            user_id=user_id,
            user_ik=diffie_helman.identity_key_prv(pem=True),
            user_ak=diffie_helman.authentication_key_prv(pem=True),
            server_ik_pub=server_ik,
            password=diffie_helman.password,
        )

    def request(self, method:str, url:str, **kwargs):
        body = requests.Request(
            method=method,
            url=url,
            data=kwargs.get("data"),
            json=kwargs.get("json"),
            files=kwargs.get("files")
        ).prepare().body or b""

        token = self.api_token.get_token(
            method=method,
            url=url,
            body=body,
        )
        kwargs["headers"] = kwargs.get("headers") or {}
        kwargs["headers"]["Authorization"] = f"Bearer {token}"
        return requests.request(method=method, url=url, **kwargs)

def register(username, diffie_helman: DiffieHelman):
    data = {
        "username": username,
        "authentication_key": diffie_helman.authentication_key_pub().decode(),
        "identity_key": diffie_helman.identity_key_pub().decode(),
        "identity_sig": diffie_helman.identity_key_sig().decode(),
    }
    response = requests.post(f"{API_URL}/auth/register", json=data, verify=ssl_verification)

    raise_for_status(response, expected_status_code=401)
    data = {
        "authenticated_challenge": ECEChallenge().compute_challenge(
            challenge=response.text,
            authentication_key=diffie_helman.authentication_key_prv(pem=True),
            identity_key=diffie_helman.identity_key_prv(pem=True),
            password=diffie_helman.password,
        )
    }
    response = requests.post(f"{API_URL}/auth/register/verify", json=data, verify=ssl_verification)
    raise_for_status(response)
    return response.json()

def put_spk(token: Token, user_id: str, diffie_helman: DiffieHelman):
    data = {
        "user_id": user_id,
        "signed_pre_keys": diffie_helman.signed_pre_keys_pub(),
    }
    response = token.request("put", f"{API_URL}/users/signed-pre-key", json=data, verify=ssl_verification)
    raise_for_status(response)

def delete_account(token: Token):
    response = token.request("delete", f"{API_URL}/users/delete-account?user_id={user_id}",
                                                     verify=ssl_verification)
    raise_for_status(response)

def token_info(token: Token):
    response = token.request("get", f"{API_URL}/auth/token", verify=ssl_verification)
    raise_for_status(response)
    return response.json()