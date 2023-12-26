
import time
import json
import logging
import hmac
import hashlib

from datetime import datetime
from pprint import pprint
from abc import ABC, abstractmethod

# Ansbile libraries
from ansible.parsing import vault
from ansible.parsing.vault import VaultSecret
from ansible.module_utils._text import to_text, to_bytes, to_native

# Oauth libraries
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


#### logger ###
#set logger config
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#create a log Handler
#fh = logging.FileHandler(filename='snow_inventory_sync.log', mode='a', encoding='utf-8')
fh = logging.StreamHandler();

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
                 token_endpoint=None,
                 json_data=None):
        
        
        if(json_data):
        
            self.from_json( json_data );
        
        else:
            self._client_id =  client_id;
            self._client_secret = client_secret;
            self._scope         = scope;
            self._api_key       = api_key;
            self._api_secure_key = b"api_secure_key"
            self._token_endpoint       = token_endpoint
            
            
    def from_json(self, json_data):

        try:
            cred_dict = json.loads(json_data);
            self._client_id     = cred_dict['client_id'];
            self._client_secret = cred_dict['client_secret'];
            self._api_key       = cred_dict['api_key'];
            self._api_secure_key = cred_dict['api_secure_key'];    
            self._token_endpoint = cred_dict['token_endpoint'];    
            self._scope = cred_dict['scope'];    
        
        except Exception as e:
            logger.exception("Error while loading credentials from json string")


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

    """Class to represet authentication object and its actions like refresh_token"""

    def __init__(self, credentials_obj:Credentials):
        
        self._credentials = credentials_obj
        oauth_client  = BackendApplicationClient(self._credentials._client_id);
        self._session = OAuth2Session(client=oauth_client)
        self._token   = None;

    @property
    def session(self):
        return(self._session)
    
    @property
    def token(self):
        return(self._token);

    @property
    def credentials(self):
        return(self._credentials);


    def refresh_token(self):
        
        try:
            
            token_response = self.session.fetch_token(

                token_url = self._credentials._token_endpoint,
                client_id = self._credentials._client_id, 
                client_secret = self._credentials._client_secret, 
                scope = self._credentials._scope
                
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


class CredentialsStoreVault():

    def __init__(self, vault_file, vault_key_file):

        self._vault_file =  vault_file;
        self._vault_key_file = vault_key_file

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
            logger.exception("Cannot Open vault_file %s", self._vault_file)

#"https://lumen.service-now.com/api/now/cmdb/instance/u_cmdb_ci_other_server/6ecb870f1beb49101504edf1b24bcb81",

class SnowCmdbApi:
    servicenow_domain = "service-now.com"
    cmdb_instance_api_path = "/api/now/cmdb/instance/"

    def __init__(self, instance, auth_session, base_url=None, cmdb_api_path=None, scheme='https', page_limit=1000):
        self.instance = instance ;
        self.authenticated_session = auth_session ;
        
        if not base_url:
            self._base_url = f"{scheme}://{self.instance}.{self.servicenow_domain}"

        if not cmdb_api_path:
            self._cmdb_api_path = self.cmdb_instance_api_path

        self._api_url = f"{self._base_url.strip('/')}/{self._cmdb_api_path.strip('/')}"
        self._page_limit = page_limit
        
        _epochTime = str(int(time.time())) ;
        
        logger.debug("epochtime: {}".format(_epochTime));

        _x_digest = hmac.new(auth_session.credentials.api_secure_key.encode(), _epochTime.encode(), digestmod=hashlib.sha256).hexdigest();
        
        logger.debug("x_digest: {}".format(_x_digest))
        logger.debug("token_type: {}".format(auth_session.token.token_type));
        
        self._api_request_headers= {
            'Authorization' : "%s %s" % (auth_session.token.token_type, auth_session.token.access_token),
            'X-Digest' : _x_digest,
            'X-Digest-Time' : _epochTime,
            'X-Application-Key': auth_session.credentials.api_key,
            'Accept' : 'application/json'
        }
        # directly set the headers in the session object instead of passing in get
        self.authenticated_session.session.headers.update(self._api_request_headers) ;
     

    @property
    def api_request_headers(self):
        return(self._api_request_headers)
    
    @property
    def api_url(self):
        return(self._api_url);

    def get_cmdb_class_url(self, cmdb_class):
        return ( "{0}/{1}".format(self.api_url.strip('/'), cmdb_class.strip('/')) );

    
        
    def get_class_ci_total_count(self, class_url, offset=0, limit=1):
        total_count = 0;
    
        _qparams = {
            'sysparm_offset':  offset,
            'sysparm_limit' :  limit
        }
        try:
            logger.debug("Trying to get total ci record counts in the class")
            logger.debug("class url: {}".format(class_url));

            resp =  self.authenticated_session.session.get(
                class_url,
                params=_qparams
            )
            logger.debug("response code: {}".format(resp.status_code))

            total_count = resp.headers['X-Total-Count'] ;

        except Exception as e:
            
            logger.exception("Error occured while getting ci list page")
            logger.warning("Error while fetching: {}".format(class_url))

        return(total_count)


    def get_ci_list_page(self, class_url, offset=0, limit=1000):
        
        ci_list = []

        _qparams = {
            'sysparm_offset':  offset,
            'sysparm_limit' :  limit
        }
        try:

            resp =  self.authenticated_session.session.get(
                class_url,
                params=_qparams
            )
            logger.debug("response code: {}".format(resp.status_code))

            resp_json = resp.json();
            result = resp_json['result'] ;

            for ci_record in result:
                ci_list.append(ci_record['sys_id']);

        except Exception as e:
            
            logger.exception("Error occured while getting ci list page")
            logger.warning("Error while fetching: {}".format(class_url))

        return(ci_list);
    
    def get_class_ci_list(self, classname, page_limit):
        
        resultset = [];
        offset = 0;
        
        _url = self.get_cmdb_class_url(classname)
        
        class_ci_count = self.get_class_ci_total_count(_url)

        logger.debug("pagination range object: start: {} stop: {} page_limit: {}".format(offset+1, class_ci_count, page_limit))

        class_ci_count = 100;
        try:

            for next_offset in range(offset+1, class_ci_count, page_limit):

                ci_sysid_list = self.get_ci_list_page(_url, next_offset, page_limit);

                resultset += ci_sysid_list
        
        except Exception as e:
        
            logger.exception("Error occured while getting ci_list for class {}".format(classname))

        return(resultset);
        

class SnowCmdbCI:
    pass

## main code


base_dir="/data01/home/ansible/ansible-practice/snow_cmdb"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;

cmdb_class_config = {
    'cmdb_ci_storage_server' : {
        'groupname' : 'storage_servers',
        'key_attrs' : [
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
        ],
        'hostname_scan_order': ['ip_address','fqdn','host_name', 'name']
    }
}

credstore = CredentialsStoreVault(vault_file, vault_password_file);

cred = credstore.get_credentials()

auth = SnowApiAuth(cred);

auth.refresh_token();

snow_api = SnowCmdbApi('lumen', auth, page_limit=10)

for cmdb_class in cmdb_class_config:
    ci_list = snow_api.get_class_ci_list(cmdb_class, 10)
    print("list of CIs in class {}".format(cmdb_class))
    print("-------------------------------------------")
    print(ci_list);


#print(auth.token.access_token);


