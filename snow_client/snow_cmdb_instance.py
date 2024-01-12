
import time
import logging
import hmac
import hashlib


class SnowCmdbApi:
    """Class that implements accessing SNOW CI through CMDB Instance API

    This is a valid and active class to consume CI, however not effecient
    for bulk consumption of several thousand CIs. use SnowTableApi instead.
    """

    servicenow_domain = "service-now.com"
    cmdb_instance_api_path = "/api/now/cmdb/instance/"

    def __init__(self, instance, auth_session, base_url=None, cmdb_api_path=None, scheme='https', page_limit=1000, ):
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

