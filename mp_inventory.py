import time
import logging
import atexit

from pprint import pprint

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowCmdbApi
import concurrent.futures

## main code

base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;
cmdb_class_config = {
    'cmdb_ci_unix_server' : {
        'groupname' : 'unix_servers',
        'req_attribs' : [
            #'sys_class_name',
            #'sys_id',
            'category',
            'subcategory',
            'operational_status',
            'install_status',
            'unverfied',
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

dev_page_limit = 100
dev_total_count = 0

credstore = CredentialsStoreVault(vault_file, vault_password_file);

auth = SnowApiAuth( credstore.get_credentials() );

auth.refresh_token();


def get_ci_details(classname, ci_list):
    sapi = SnowCmdbApi('lumen', auth, page_limit=dev_page_limit, test_ci_count=dev_total_count)
    details = sapi.get_ci_details(classname, ci_list, cmdb_class_config[classname])
    return(details)


host_count = 0
ci_details = [];
results = []

snow_api = SnowCmdbApi('lumen', auth, page_limit=dev_page_limit, test_ci_count=dev_total_count)
with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:

    for cmdb_class in cmdb_class_config:
        for ci_id_list in snow_api.get_class_ci_list(cmdb_class):
            for ci_id in ci_id_list:
                results = {executor.submit(get_ci_details, cmdb_class, ci_id): ci_id for ci_id in ci_id_list}

    for r in concurrent.futures.as_completed(results.keys()):
        pprint(r.result())
