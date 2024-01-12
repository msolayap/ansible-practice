
import time
import json
import logging
import hmac
import hashlib
import re

from datetime import datetime
from pprint import pprint
from abc import ABC, abstractmethod

# Oauth libraries
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import urllib.parse


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
        #print("by_time: {}, expiry: {}".format(by_time.ctime(), 
        #                                       datetime.fromtimestamp(self._expiry_timestamp).ctime())
        #);

        if(self._expiry_timestamp <= by_time.timestamp()):
            """Token expired"""
            return(True);
        else:
            """Token still valid"""
            return(False);
                
class OAuthCredentials:
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
            logging.exception("Error while loading credentials from json string")


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

    def __init__(self, credentials_obj:OAuthCredentials):
        
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
            
            logging.exception("Error while getting new token")
            
            return(False)

class SnowCmdbCIParser(ABC):

    true_expression = re.compile(r'^(true|yes)$', re.IGNORECASE)
    false_expression = re.compile(r'^(false|no)$', re.IGNORECASE)

    @classmethod
    def is_true(cls, val):
        if isinstance( val , str ):
            if(0 < int(val) ):
                """for values like 6, 7, 8 instead of 1"""
                return(True)
            elif( cls.true_expression.match( val ) ):
                """ true or yes"""
                return(True)
            else:
                return(False)
            
        return( bool(val) )
    
    @classmethod
    def is_false(cls, val):
        if isinstance( val , str ):
            if(1 > int(val)):
                """ for values like 0 or lesser"""
                return(True)
            if( cls.false_expression.match( val ) ):
                """ false or no"""
                return(True)
            else:
                return(False);
    
        return( not bool(val) )

    def __init__(self, ci_details:dict=None):
        if(ci_details):
            self._ci_details = ci_details

    @property
    @abstractmethod
    def ci_details(self):
        pass

    @abstractmethod
    def get_ci_hostname(self):
        pass

    @abstractmethod
    def pickup_required_attributes(self, req_attribs=None):
        pass

    @abstractmethod
    def is_valid_hostname(self, ci_name):
        pass

    @abstractmethod
    def is_active_ci(self):
        pass
        

class SnowCmdbCIGenericParser(SnowCmdbCIParser):
    def __init__(self, ci_details:dict=None):
        self.ci_details = ci_details
    
    @property
    def ci_details(self):
        return(self._ci_details)
    
    @ci_details.setter
    def ci_details(self, cid):
        self._ci_details = cid

    def process_ci_record(self, class_config):
        
        req_ci_attribs = dict()

        try:

            print(" ------------ class config received in process record ----------")
            pprint(class_config)
            print(" ---------------------------------------------------------------")

            # primary identifier to address this CI from top level processes
            # one of the ip_address, fqdn, host_name, name, etc.,

            ansible_hostname_attrib = class_config.get('ansible_hostname_attrib',None)

            ci_name  = self.get_ci_hostname(class_config['hostname_scan_order']);
            

            if( class_config.get("valid_hostname_only", False) == True ):
                """ if the config demands filtering only valid hostnames"""
                
                if(not self.is_valid_hostname(ci_name)):
                    """ Not having valid hostname or fqdn or ip address. This CI is useless for inventory"""

                    return(req_ci_attribs) # return empty dict
            
            elif (not self.is_active_ci()):
                """ CI not yet installed or operational """

                return(req_ci_attribs) # return empty dict
            
            #logging.debug("ci record valid, picking required fields")

                       
            req_ci_attribs = self.pickup_required_attributes(class_config['req_attribs'])
            
            req_ci_attribs.update({'x_ci_identifier': ci_name})
            
            if(ansible_hostname_attrib):
                req_ci_attribs.update( { 'ansible_hostname': self.get_ci_attrib(ansible_hostname_attrib) } )

            
        except Exception as e:

            logging.exception("Exception occured while getting ci_details")

        return(req_ci_attribs)

    
    def get_ci_attrib(self, ci_attrib_key):
        return(self.ci_details[ci_attrib_key])
    
    def get_ci_hostname(self, scan_order):
        
        id_candidates = list()
        ci_identifier = None
        try:

            # ['name','fqdn','host_name','ip_address']
            for attrib in scan_order:
                id_candidates.append(self.ci_details.get(attrib, ""))

            # return the first non null value.
            
            ci_identifier = next((val for val in id_candidates if val.strip() !=  ""), None)
        except Exception as e:
            logging.error("Error occured while finding hostname: {}".format(e))
            raise
        
        return(ci_identifier)

    def pickup_required_attributes(self, req_attribs=None):
        # pickup only required attributes
        picked_attribs = dict()
        
        if(req_attribs is not None):
            picked_attribs = {k:v for k,v in self.ci_details.items() if k in req_attribs}

        return(picked_attribs);

    @classmethod
    def is_fqdn(cls, hostname: str) -> bool:
        """
        courtesy:
        https://codereview.stackexchange.com/questions/235473/fqdn-validation
        """
        if not 1 < len(hostname) < 253:
            return False

        # Remove trailing dot
        if hostname[-1] == '.':
            hostname = hostname[0:-1]

        #  Split hostname into list of DNS labels
        labels = hostname.split('.')

        #  Define pattern of DNS label
        #  Can begin and end with a number or letter only
        #  Can contain hyphens, a-z, A-Z, 0-9
        #  1 - 63 chars allowed
        fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

        # Check that all labels match that pattern.
        return all(fqdn.match(label) for label in labels)
    
    @classmethod
    def is_valid_hostname(cls, ci_name):
        """
        method to verify a valid hostname or ip. 
        if none of the scanned fields have valid name or
        if the name contains only numerical values e.g 1588383.9298
        skip this ci - not useful

        """
        # is_fqdn should cover for fqdn and ip address
        
        if(ci_name is None):
            return(False)

        if( not cls.is_fqdn(ci_name) ):
                return(False)
        
        elif( re.match(r'^\d{4,}', ci_name) or
            re.match(r'^[\d.]+$', ci_name) or
            re.search(r'[^a-z0-9\-.]', ci_name, re.IGNORECASE)
            ): 
            return(False)
        else:
            return(True)
    
    # method to verify validity of the CI record for sync
    def is_active_ci(self):
        
        if ( self.ci_details['hardware_status'] == "installed" and
             self.is_true(self.ci_details.get('install_status', False)) and 
             self.is_true(self.ci_details.get('operational_status', False))
           ):
            
            return (True)
        
        else:

            return(False)

class SnowTableApi:
    servicenow_domain = "service-now.com"
    table_api_path = "/api/now/v2/table/"

    def __init__(self, instance, auth_session, base_url=None, cmdb_api_path=None, scheme='https', page_limit=1000, test_ci_count=40):
        self.instance = instance ;
        self.authenticated_session = auth_session ;
        
        if not base_url:
            self._base_url = f"{scheme}://{self.instance}.{self.servicenow_domain}"

        if not cmdb_api_path:
            self._cmdb_api_path = self.table_api_path

        self._api_url = f"{self._base_url.strip('/')}/{self._cmdb_api_path.strip('/')}"
        self._page_limit = page_limit
        self._test_ci_count = test_ci_count ;
        
        _epochTime = str(int(time.time())) ;
        
        _x_digest = hmac.new(auth_session.credentials.api_secure_key.encode(), _epochTime.encode(), digestmod=hashlib.sha256).hexdigest();
        
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
            
            logging.debug("class url: {}".format(class_url));

            resp = self.authenticated_session.session.get(class_url, params=_qparams);
            
            """ for some classes this header value is missing, so assume 0 for them """
            total_count = resp.headers.get('X-Total-Count', 0)

        except Exception as e:
            
            logging.exception("Error occured while getting ci list page")
            logging.warning("Error while fetching: {}".format(class_url))

        if(self._test_ci_count == 0):

            return(int(total_count)) 

        else:
            return(self._test_ci_count)

    @classmethod    
    def get_urlencoded(cls, fields_list=None):
        """method to urlencode sysparm_fields """

        if(not isinstance(fields_list, list)):

            return( urllib.parse.quote(fields_list) )
        else:
            return( urllib.parse.quote(",".join(fields_list))  )

    def get_ci_list_page(self, class_url, offset=0, limit=1000, qparams=None):
        
        result = []

        _qparams = {
            'sysparm_offset':  offset,
            'sysparm_limit' :  limit
        }

        if(qparams != None):

            _qparams.update(qparams)

        try:

            resp =  self.authenticated_session.session.get(
                class_url,
                params=_qparams
            )
            
            resp_json = resp.json();
            result = resp_json['result'] ;

            return(result)


        except Exception as e:
            
            logging.exception("Error occured while getting ci list page")
            logging.warning("Error while fetching: {}".format(class_url))

        return(result)

        
    
    def get_ci_list(self, classname, page_limit=None, fields_list=tuple()):
        
        ci_list = [];
        query_params = {}
        offset = 0;

        if ( page_limit is None):

            if(self._page_limit > 0 ):

                page_limit = self._page_limit

            else:

                page_limit = 1000; # hard limit if nothing is set.
        
        _url = self.get_cmdb_class_url(classname)
        
        class_ci_count = self.get_class_ci_total_count(_url)

        logging.debug("pagination range object: start: {} stop: {} page_limit: {}".format(offset+1, class_ci_count, page_limit))

        if(fields_list):

            query_params.update({'sysparm_field' : self.get_urlencoded(fields_list) } )

                
        try:

            for next_offset in range(offset+1, class_ci_count, int(page_limit)):

                ci_list = self.get_ci_list_page(_url, next_offset, page_limit, query_params);

                yield( ci_list )
        
        except Exception as e:
        
            logging.exception("Error occured while getting ci_list for class {}".format(classname))

        return(ci_list);

    
    
class SnowCmdbApi:

    servicenow_domain = "service-now.com"
    cmdb_instance_api_path = "/api/now/cmdb/instance/"

    def __init__(self, instance, auth_session, base_url=None, cmdb_api_path=None, scheme='https', page_limit=1000, test_ci_count=40):
        self.instance = instance ;
        self.authenticated_session = auth_session ;
        
        if not base_url:
            self._base_url = f"{scheme}://{self.instance}.{self.servicenow_domain}"

        if not cmdb_api_path:
            self._cmdb_api_path = self.cmdb_instance_api_path

        self._api_url = f"{self._base_url.strip('/')}/{self._cmdb_api_path.strip('/')}"
        self._page_limit = page_limit
        self._test_ci_count = test_ci_count ;
        
        _epochTime = str(int(time.time())) ;
        
        _x_digest = hmac.new(auth_session.credentials.api_secure_key.encode(), _epochTime.encode(), digestmod=hashlib.sha256).hexdigest();
        
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
            
            logging.debug("class url: {}".format(class_url));

            resp = self.authenticated_session.session.get(class_url, params=_qparams);
            
            """ for some classes this header value is missing, so assume 0 for them """
            total_count = resp.headers.get('X-Total-Count', 0)

        except Exception as e:
            
            logging.exception("Error occured while getting ci list page")
            logging.warning("Error while fetching: {}".format(class_url))

        if(self._test_ci_count == 0):
            return(int(total_count)) 
        else:
            return(self._test_ci_count)


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
            
            resp_json = resp.json();
            result = resp_json['result'] ;

            for ci_record in result:
                ci_list.append(ci_record['sys_id']);

        except Exception as e:
            
            logging.exception("Error occured while getting ci list page")
            logging.warning("Error while fetching: {}".format(class_url))

        return(ci_list);

        
    
    def get_class_ci_list(self, classname, page_limit=None):
        
        resultset = [];
        offset = 0;

        if ( page_limit is None):
            if(self._page_limit > 0 ):
                page_limit = self._page_limit
            else:
                page_limit = 4000; # hard limit if nothing is set.
        
        _url = self.get_cmdb_class_url(classname)
        
        class_ci_count = self.get_class_ci_total_count(_url)

        logging.debug("pagination range object: start: {} stop: {} page_limit: {}".format(offset+1, class_ci_count, page_limit))
                
        try:
            """ Fetch all the CIs of the class page by page considering page_limit config"""
            for next_offset in range(offset+1, class_ci_count, int(page_limit)):

                ci_sysid_list = self.get_ci_list_page(_url, next_offset, page_limit);

                #resultset += ci_sysid_list
                yield( ci_sysid_list )
        
        except Exception as e:
        
            logging.exception("Error occured while getting ci_list for class {}".format(classname))

        #return(resultset);

    
    def get_ci_details(self, classname, ci_id, class_config):
        
        ci_attribs = dict()
        req_ci_attribs = dict()

        _url =  self.get_cmdb_class_url(classname)

        try:

            ci_url = "{}/{}".format(_url.strip('/'), ci_id)
            resp = self.authenticated_session.session.get(ci_url)

            resp_json  = resp.json()
            ci_attribs = resp_json['result']['attributes']
            
            # pick only required attributes for host var preparation. 
            ci_parser = SnowCmdbCIGenericParser(ci_attribs)

            # primary identifier to address this CI from top level processes
            # one of the ip_address, fqdn, host_name, name, etc.,

            ci_name        = ci_parser.discover_ci_identifier(class_config['hostname_scan_order']);

            
            if(not ci_parser.is_valid_hostname(ci_name)):
                return(req_ci_attribs)
            
            elif (not ci_parser.is_active_ci()):
                """ CI not yet installed or operational """
                return(req_ci_attribs)
            
            #logging.debug("ci record valid, picking required fields")
            req_ci_attribs = ci_parser.pickup_required_attributes(class_config['req_attribs'])
            req_ci_attribs.update({'x_ci_identifier': ci_name})
            
        except Exception as e:

            logging.exception("Exception occured while getting ci_details")

        return(req_ci_attribs)
