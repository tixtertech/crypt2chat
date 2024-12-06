from urllib.parse import urlencode

import requests
from common.security import *

API_URL = os.getenv("API_URL")
ssl_verification = False if os.getenv("VERIFY_CERT") == "false" else True

def get_user_infos(user_id=None, username=None):
    if user_id:
        response = requests.get(f"{API_URL}/users/id/{user_id}", verify=ssl_verification)
        response.raise_for_status()
        return response.json()

    elif username:
        response = requests.get(f"{API_URL}/users/name/{username}", verify=ssl_verification)
        response.raise_for_status()
        return response.json()
    else:
        raise ValueError("you must specify at least one argument")

def get_user(search=None, since=None, limit=None):
    params = {}
    if search:
        params['search'] = search
    if since:
        params['since'] = since
    if limit:
        params['limit'] = limit

    query_string = f"?{urlencode(params)}" if params else ""
    url = f"{API_URL}/users{query_string}"

    response = requests.get(url, verify=ssl_verification)
    response.raise_for_status()
    return response.json()
