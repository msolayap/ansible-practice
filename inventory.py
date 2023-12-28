import time
import logging
import atexit

from pprint import pprint

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowCmdbApi

## main code

base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;
cmdb_class_config = {
    'u_cmdb_ci_other_server' : {
        'groupname' : 'other_servers',
        'req_attribs' : [
            #'sys_class_name',
            #'sys_id',
            'os'
        ],
        'hostname_scan_order': ['ip_address','fqdn','name','host_name']
        
    }
}

start = time.time();

def end_tasks():
    end = time.time();
    print("\nFinished in -> {:.2f} seconds".format(round((end - start), 2)));

atexit.register(end_tasks)

#### logger ###

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.WARNING, datefmt='%Y-%m-%d-%H:%M:%S');

#logger = logging.getLogger("snow_inventory")
#logger.setLevel(logging.DEBUG)

#fh = logging.StreamHandler();
#fh.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d-%H:%M:%S')
#fh.setFormatter(formatter);
#logger.addHandler(fh)
##########################

dev_page_limit = 10; 
dev_total_count = 40 ;

credstore = CredentialsStoreVault(vault_file, vault_password_file);

cred = credstore.get_credentials()

auth = SnowApiAuth(cred);

auth.refresh_token();

snow_api = SnowCmdbApi('lumen', auth, page_limit=dev_page_limit, test_ci_count=40)

host_count = 0
for cmdb_class in cmdb_class_config:
    for ci_id_list in snow_api.get_class_ci_list(cmdb_class):
        ci_detail = snow_api.get_ci_details(cmdb_class, ci_id_list, cmdb_class_config[cmdb_class])
        pprint(ci_detail)
