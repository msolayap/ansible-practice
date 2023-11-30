#python

import requests;
from pprint import pprint ;


from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth;

token_endpoint="https://login.microsoftonline.com/72b17115-9915-42c0-9f1b-4f98e5a4bcd2/oauth2/v2.0/token"
client_id = "f5dc7ffd-9be5-407a-b093-56a579ae9d85"
client_secret = "kOy8Q~jxyWde~AiNzYjdG_gZdc1ljO6ERDyzvcPw"
api_key = "APPKEY759512020091415435175420415"
api_secure_key = "AKI030662020091415435175463219"
scope="api://f5dc7ffd-9be5-407a-b093-56a579ae9d85/.default"
access_token = None ;
token_response={}

print ("my name is vpk");

oauth_client  = BackendApplicationClient(client_id);
oauth_session = OAuth2Session(client=oauth_client)
token_response = oauth_session.fetch_token(token_url=token_endpoint, client_id=client_id, client_secret=client_secret, scope=scope);

if token_response:
    pprint(token_response.get('access_token', None));


