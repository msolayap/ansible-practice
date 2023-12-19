
from oauthclient import snow_cmdb_api, oauth_token, credentials
import datetime 
import json

token_response = b"""
{
    "token_type": "Bearer",
    "expires_in": 3599,
    "ext_expires_in": 3599,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi"
}
"""
td =  json.loads(token_response) ;

token = oauth_token(
        token=td['access_token'],
        token_expires_in=td['expires_in'], 
        token_fetched_time=datetime.fromtimestamp(1702470013), 
        token_type=td['token_type']
        );

print("Token {}".format(("expired" if token.is_expired() == True else "valid")));

print(token.token_type);

print (" --- credential usage ---");

creds = credentials(
    client_id=client_id,
    client_secret=client_secret,
    scope=scope,
    api_key=api_key,
    api_secure_key=api_secure_key,
    token="myoldtoken"
    );

print("client_id = {}".format(creds.client_id));
print("token = {}".format(creds.token));
creds.token = "newtoken";
print("new token = {}".format(creds.token));
#print("-- cred store usage ---")
#credstore = credentials_store_vault(creds);
#credstore.get_fresh_token();
print("--- snow api usage ---");
cmdb_api = snow_cmdb_api('lumen');

print("Api base url: {}".format(cmdb_api.api_url));
print("Api Class base url: {}".format(cmdb_api.get_cmdb_class_url('cmdb_ci_server')));

