#python

# primary api library
import requests;

#utility libraries
from pprint import pprint ;
import time 
import hashlib
import hmac

# Oauth libraries
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth;

token_endpoint="https://login.microsoftonline.com/72b17115-9915-42c0-9f1b-4f98e5a4bcd2/oauth2/v2.0/token"
client_id = "f5dc7ffd-9be5-407a-b093-56a579ae9d85"
client_secret = "kOy8Q~jxyWde~AiNzYjdG_gZdc1ljO6ERDyzvcPw"
api_key = "APPKEY759512020091415435175420415"
api_secure_key = b"AKI030662020091415435175463219"
scope="api://f5dc7ffd-9be5-407a-b093-56a579ae9d85/.default"
access_token = None ;
token_response={}

print ("my name is vpk");

oauth_client  = BackendApplicationClient(client_id);
oauth_session = OAuth2Session(client=oauth_client)
token_response = oauth_session.fetch_token(token_url=token_endpoint, client_id=client_id, client_secret=client_secret, scope=scope);

if token_response:
    print("Token type obtained: %s" % (token_response.get('token_type')));


# get current time in epoch format. Then convert it to bytesarray for hmac library.

epochTime = str(int(time.time()));
b_epochTime = epochTime.encode();

x_digest = hmac.new(api_secure_key, b_epochTime, digestmod=hashlib.sha256).hexdigest(); 

api_headers= {
   'Authorization' : "%s %s" % (token_response.get('token_type'), token_response.get('access_token')),
   'X-Digest' : x_digest,
   'X-Digest-Time' : epochTime,
   'X-Application-Key': api_key,
   'Accept' : 'application/json'
}

query_params = { 
    'sysparm_limit' : 1
}

#pprint(api_headers);
#print();
response = requests.get(
    "https://lumen.service-now.com/api/now/cmdb/instance//u_cmdb_ci_other_server/6ecb870f1beb49101504edf1b24bcb81",
    headers=api_headers,
    params=query_params
    );

if response.status_code == 200:
    print('Success!')
elif response.status_code == 404:
    print('Not Found.')

key_fields = (
'operational_status',
'classification',
'last_discovered',
'sys_class_name',
'fqdn',
'sys_id',
'ip_address',
'category',
'host_name',
'name',
'subcategory',
'used_for',
'virtual',
'discovery_source'
 ) ;

result = response.json();
attributes = result['result']['attributes'] ;

imp_keys =  {k:v for k,v in attributes.items() if k in key_fields}

pprint(imp_keys)