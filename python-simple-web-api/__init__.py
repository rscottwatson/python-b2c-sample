import json
import os
import logging
from six.moves.urllib.request import urlopen
from functools import wraps

from flask import Flask, request, jsonify, _request_ctx_stack
from flask_cors import cross_origin
from jose import jwt

app = Flask(__name__)

# Provide the B2C Tenant name, specify the non-MFA B2C Policy name, and the API client id
TENANT_NAME = os.getenv('B2C_TENANT_NAME')
B2C_POLICY = os.getenv('BC2_SIGN_UP_IN_POLICY')
API_AUDIENCE = os.getenv('API_CLIENT_ID')

# Enable logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Function to load the accounts from the accounts file
def load_accounts():
    try:
        with open('accounts.json') as file:
            accounts = json.loads(file.read())
            return accounts
    except Exception as e:
        logging.error('Unable to load accounts file')
        logging.error('Error: ', exc_info=True)

# Function to update the beneficiary in the accounts info
def update_accounts(accounts):
    try:
        with open('accounts.json', '+w') as file:
            file.write(json.dumps(accounts))
    except Exception as e:
        logging.error('Unable to load accounts file')
        logging.error('Error: ', exc_info=True)

# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    print('handling error')
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Validate the header provided in the token
def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                         "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must start with"
                         " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must be"
                         " Bearer token"}, 401)

    token = parts[1]
    return token

# Validat the access token by verifying the signature based upon the certificate used to sign it
def requires_auth(f):
    """Determines if the Access Token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token_auth_header()
            jsonurl = urlopen("https://" +
                              TENANT_NAME + ".b2clogin.com/" +
                              TENANT_NAME + ".onmicrosoft.com/" +
                              B2C_POLICY + "/discovery/v2.0/keys")
            jwks = json.loads(jsonurl.read())
            unverified_header = jwt.get_unverified_header(token)
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Unable to parse authentication"
                             " token."}, 401)
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience=API_AUDIENCE,
                    issuer="https://" + TENANT_NAME +
                    ".b2clogin.com/2431b218-604e-49e5-b0e4-c184facb0304/v2.0/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                 "incorrect claims,"
                                 "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)
            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)
    return decorated

def requires_scope(required_scope):
    """Determines if the required scope is present in the Access Token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scp"):
        token_scopes = unverified_claims["scp"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False

# Retrieve the policy information from the accounts file
def retrieve_policy_information():
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    email_addresses = unverified_claims["emails"]
    accounts = load_accounts()
    for email in email_addresses:
        for account in accounts:
            if account['email'] == email:
                return(account)
    return "Record not found"

# Update the policy information in the accoutns file
def update_policy_information(new_beneficiary):
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    email_addresses = unverified_claims["emails"]
    accounts = load_accounts()
    for email in email_addresses:
        for account in accounts:
            if account['email'] == email:
                account['beneficiary'] = new_beneficiary
                update_accounts(accounts)
                return 'Success'
            else:
                return 'Error.  Unable to update'

# Controllers API

# This endpoint does not require authentication and is used to validate the API is reachable
@app.route("/public")
@cross_origin(allow_headers=['Content-Type', 'Authorization'])
def public():
    response = "Successfully accessed the public API endpoint!"
    return response

# Display the user's account information
@app.route("/acctinfo")
@cross_origin(allow_headers=['Content-Type', 'Authorization'])
@requires_auth
def acctinfo():
    if requires_scope("Account.Read"):
        account = retrieve_policy_information()
        if account == "Record not found":
            return "Record not found", 400
        return jsonify(account)
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)

# Endpoint which updates the user's account information
@app.route("/acctupdate")
@cross_origin(allow_headers=['Content-Type', 'Authorization'])
@requires_auth
def acctudpate():
    if requires_scope("Account.Write"):
        result = update_policy_information(request.args.get('name'))
        if result == 'Success':
            return 'Success'
        else:
            return 'Failure'
    raise AuthError({
        "code": "Unauthorized",
        "description": "You don't have access to this resource"
    }, 403)

# This allows a user to set a color

if __name__ == '__main__':
    app.run()
