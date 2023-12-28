

import time
import atexit 
import logging;

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowCmdbApi

#### execution time calc ####
start   = time.time()
def end_task():
    print("Finished in -> {} seconds".format( int(time.time() - start)))
atexit.register(end_task);

##### logging configuration ###

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", 
                    datefmt="%Y-%m-%d-%H:%M:%S"
                    level=logging.DEBUG
                    )

#### initial configuration ###
base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;

cmdb_class_list =  list()
with open("all_classes.txt") as clist:
    for cmdb_class in clist:
        cmdb_class_list.append(cmdb_class.strip())


credstore = CredentialsStoreVault(vault_file, vault_password_file)
cred = credstore.get_credentials()
auth = SnowApiAuth(cred)
auth.refresh_token()
snow_api = SnowCmdbApi('lumen', auth, page_limit=10, test_ci_count=10000000)

for cmdb_class in cmdb_class_list:
    clsurl = snow_api.get_cmdb_class_url(cmdb_class);
    ci_count = snow_api.get_class_ci_total_count(clsurl)
    print("{} - {}".format(cmdb_class, ci_count))
    time.sleep(5);