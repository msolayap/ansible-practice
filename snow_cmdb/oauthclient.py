
import time
import json
import logging

from datetime import datetime
from pprint import pprint
from abc import ABC, abstractmethod

# Ansbile libraries
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
from ansible.module_utils import to_text, to_bytes, to_native

# Oauth libraries
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

token_endpoint="https://login.microsoftonline.com/72b17115-9915-42c0-9f1b-4f98e5a4bcd2/oauth2/v2.0/token"
client_id = "f5dc7ffd-9be5-407a-b093-56a579ae9d85"
client_secret = "kOy8Q~jxyWde~AiNzYjdG_gZdc1ljO6ERDyzvcPw"
api_key = "APPKEY759512020091415435175420415"
api_secure_key = b"AKI030662020091415435175463219"
scope="api://f5dc7ffd-9be5-407a-b093-56a579ae9d85/.default"
access_token = None ;
token_response={}

#### logger ###
#set logger config
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#create a log Handler
fh = logging.FileHandler(filename='snow_inventory_sync.log', mode='a', encoding='utf-8')

#set Handler config
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d-%H:%M:%S')
fh.setFormatter(formatter);
logger.addHandler(fh)
##########################



class OAuthToken:

    """Class to hold Token information and provides verification methods for the validity of the token
    Args:
        token: actual token string
        token_expires_in: validity of token in seconds from the token generation time - e.g 300 = 5 minutes
        token_fetched_time: token reception time or current time.
        token_type: type of token - default Bearer

    Returns:
        OAuthToken Object

    EXAMPLES:

    token_response = b"
    {
        "token_type": "Bearer",
        "expires_in": 3599,
        "ext_expires_in": 3599,
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOi",
    }
    "
    td =  json.loads(token_response) ;

    token = OAuthToken(
            token=td['access_token'],
            token_expires_in=td['expires_in'], 
            token_fetched_time=datetime.now(), 
            token_type=td['token_type']
            );

    print("Token {}".format(("expired" if token.is_expired() == True else "valid")));

    print(token.get_token_type());
"""

    
    def __init__(self, 
                 token:str, 
                 token_expires_in:int=0, 
                 token_fetched_time=datetime.now(),
                 token_type:str="Bearer", **kwargs):
        
        self._access_token = token ;
        self._token_expires_in = token_expires_in
        self._token_fetched_time = token_fetched_time 
        self._token_type = token_type

        self._expiry_timestamp = self.calc_expiry_timestamp(token_fetched_time, token_expires_in)
        
        #if there are any other attributes sent, make it as object vars.
        for k,v in kwargs.items():
            setattr(self, k, v);
    
    @classmethod
    def calc_expiry_timestamp(self, time1:datetime, interval:int):
        return(int(time1.timestamp()) + int(interval));

    @property
    def access_token(self):
        return(self._access_token)
        
    @property
    def expires_in(self):
        return self._token_expires_in
    
    @property
    def token_type(self):
        return self._token_type
    
    @property
    def token_fetched_time(self):
        return self._token_fetched_time 

    
    def update_token(self, token_dict):
        self._access_token = token_dict['access_token'] ;
        self._token_expires_in = token_dict['expires_in']
        self._token_type = token_dict['token_type']
        self._token_fetched_time = token_dict.get('fetched_time', datetime.now())
        self._expiry_timestamp = self.calc_expiry_timestamp(self._token_fetched_time, int(self._token_expires_in));
    
    def is_expired(self, by_time=datetime.now()):
        """Method to verify the token's validity. i.e if its expired or valid. 
        
        Parameters:
            by_time: int
                a timestamp to compare the token's expiry time against. 
                by default this is current time.
        Returns: bool
            True - if the token expired
            False - token not expired or still valid.

        """
        print("by_time: {}, expiry: {}".format(by_time.ctime(), 
                                               datetime.fromtimestamp(self._expiry_timestamp).ctime())
        );

        if(self._expiry_timestamp <= by_time.timestamp()):
            """Token expired"""
            return(True);
        else:
            """Token still valid"""
            return(False);
                

class Credentials:
    """Object to represet credentials as a whole"""

    def __init__(self, 
                 client_id=None, 
                 client_secret=None,
                 scope=None,
                 api_key=None,
                 api_secure_key=None,
                 json_data=None):
        
        
        if(json_data):
        
            self.from_json( json_data );
        
        else:
            self._client_id =  client_id;
            self._client_secret = client_secret;
            self._scope=scope;
            self._api_key=api_key;
            self._api_secure_key=api_secure_key;
            
            
    def from_json(self, json_data):
        
        try:
            cred_dict = json.loads(json_data);
            self.client_id = cred_dict['client_id'];
            self.client_secret = cred_dict['client_secret'];
            self.api_key = cred_dict['api_key'];
            self.api_secure_key = cred_dict['api_secure_key'];    
        
        except Exception as e:
            logger.warning("Error while loading credentials from json string")

    @property
    def client_id(self):
        return(self._client_id);

    @property
    def client_secret(self):
        return(self._client_secret);

    @property
    def scope(self):
        return(self._scope);

    @property
    def api_key(self):
        return(self._api_key);
    
    @property
    def api_secure_key(self):
        return(self._api_secure_key);
    
class SnowApiAuth:

    def __init__(self, credentials_obj:Credentials):
        
        self._credentials = credentials_obj
        oauth_client  = BackendApplicationClient(self._credentials.client_id)
        self._session = OAuth2Session(client=oauth_client)
        self._token   = None;

    @property
    def session(self):
        return(self._session)
    
    @property
    def token(self):
        return(self._token);


    def refresh_token(self):
        
        try:
            
            token_response = self.session.fetch_token(

                token_url = self._credentials.token_endpoint,
                client_id = self._credentials.client_id, 
                client_secret = self._credentials.client_secret, 
                scope = self._credentials.scope
                
                );
            
            self._token = OAuthToken(
                
                token              = token_response['access_token'],
                token_expires_in   = token_response['expires_in'],
                token_type         = token_response['token_type'],
                token_fetched_time = datetime.now()
                
                )
            
            return(True);
    
        except Exception as e:
            
            logger.exception("Error while getting new token")
            
            return(False)

# class credentials_store():
#     """Base class for credentials store. just define a dict key based store"""

#     def __init__(self, storekey, cred:credentials):
#         self._credentials[storekey] = cred
#         pass
    
#     def get_credentials(self, storekey):
#         return(self._credentials.get(storekey, None))
    
#     def store_credentials(self, storekey, cred:credentials):
#         self._credentials[storekey] = cred ;
    
    
class CredentialsStoreVault():

    def __init__(self, vault_file, vault_key_file):

        self._vault_file =  vault_file;
        self._vault_key_file = vault_key_file

    def get_credentials_dummy(self):

        dummy_vault_content = {
            'token_endpoint' : "https://login.microsoftonline.com/72b17115-9915-42c0-9f1b-4f98e5a4bcd2/oauth2/v2.0/token",
            'client_id'      : r"f5dc7ffd-9be5-407a-b093-56a579ae9d85",
            'client_secret'  : r"kOy8Q~jxyWde~AiNzYjdG_gZdc1ljO6ERDyzvcPw",
            'api_key'        : r"APPKEY759512020091415435175420415",
            'api_secure_key' : b"AKI030662020091415435175463219",
            'scope'          : "api://f5dc7ffd-9be5-407a-b093-56a579ae9d85/.default"            
        }

        return( Credentials(json_data=dummy_vault_content) )

    def get_credentials(self):
        try:
            with open(self._vault_key_file, "r") as vkf:
                vault_password = vkf.read();
            
            with open(self._vault_file, "r") as vf:
                encrypted_data = vf.read()
                logger.info("Vault content read")
                
                vault_ref = vault.VaultLib(
                    [("default", VaultSecret(_bytes=to_bytes(vault_password.strip())))]
                )
                
                decrypted_data = vault_ref.decrypt(encrypted_data.strip())

                if(decrypted_data != None):
                    return (Credentials(json_data=decrypted_data));
    
        except Exception as e:
            logger.error("Cannot Open vault_file %s", self._vault_file)

#"https://lumen.service-now.com/api/now/cmdb/instance/u_cmdb_ci_other_server/6ecb870f1beb49101504edf1b24bcb81",

class snow_cmdb_api:
    servicenow_domain = "servcice-now.com"
    cmdb_instance_api_path = "/api/now/cmdb/instance/"

    def __init__(self, instance, base_url=None, cmdb_api_path=None, scheme='https'):
        self.instance = instance ;
        
        if not base_url:
            self._base_url = f"{scheme}://{self.instance}.{self.servicenow_domain}"

        if not cmdb_api_path:
            self._cmdb_api_path = self.cmdb_instance_api_path

        self._api_url = f"{self._base_url.strip('/')}/{self._cmdb_api_path.strip('/')}"


    @property
    def api_url(self):
        return(self._api_url);

    def get_cmdb_class_url(self, cmdb_class):
        return ( "{0}/{1}".format(self.api_url.strip('/'), cmdb_class.strip('/')) );


class SnowCmdbCI:
    pass


vault_file          = "./vault_lumen_snow"
vault_password_file = "./lumen_snow_password"

credstore = CredentialsStoreVault(vault_file, vault_password_file);

cred = credstore.get_credentials_dummy()

auth = snow_api_auth(cred);

auth.refresh_token();

print(auth.token.access_token);

