import types
import json

from jose import jwt

def feed_session_with_raw_token(oidc, raw_access_token):
    """
        Permet de créer une session avec un nouveau token. Cette
        situation arrive lorsque l'on fait un login ou création de compte
        manuel. Dans ce cas oidc n'est pas au courant de la session et on doit
        l'informer pour que la sessio et décorateur (ex @require_login) fonctionnent.
    """
    import time
    import datetime
    from datetime import timedelta

    access_info                  = json.loads(raw_access_token)
    access_info["client_id"]     = oidc.client_secrets['client_id']
    access_info["client_secret"] = oidc.client_secrets['client_secret']
    access_info["token_uri"]     = oidc.client_secrets['token_uri']
    access_info["user_agent"]    = None
    access_info["invalid"]       = False
    access_info["revoke_uri"]    = ""
    # avec la bonne date d'expiration
    token_expire_sec             = access_info["expires_in"]
    now                          = datetime.datetime.now()
    token_expire_at              = now + timedelta(seconds=token_expire_sec)
    access_info["token_expiry"]  = token_expire_at.isoformat()

    access_token     = access_info["access_token"]
    raw_access_token = json.dumps(access_info)
    tkn_decoded      = jwt.get_unverified_claims(access_token)
    # session set
    oidc.credentials_store[tkn_decoded['sub']] = raw_access_token
    oidc._set_cookie_id_token(id_token=tkn_decoded)
