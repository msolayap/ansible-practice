

import time
import atexit 
import logging;

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowCmdbApi
from concurrent.futures import ThreadPoolExecutor, as_completed

#### execution time calc ####
start   = time.time()
def end_task():
    print("Finished in -> {} seconds".format( int(time.time() - start)))
atexit.register(end_task);

##### logging configuration ###

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", 
                    datefmt="%Y-%m-%d-%H:%M:%S",
                    level=logging.DEBUG
                    )

#### initial configuration ###
base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;

cmdb_class_list =  list()
with open("all_classes.txt", "r") as clist:
    for cmdb_class in clist:
        cmdb_class_list.append(cmdb_class.strip())

logging.info("{} classes found".format(len(cmdb_class_list)))

credstore = CredentialsStoreVault(vault_file, vault_password_file)

credentials = credstore.get_credentials()

auth = SnowApiAuth(credentials)
auth.refresh_token()

class_count = dict()

def get_class_ci_count(cmdb_class, authobj):
    snow_api = SnowCmdbApi('lumen', authobj, page_limit=20, test_ci_count=0)
    clsurl = snow_api.get_cmdb_class_url(cmdb_class);
    ci_count = snow_api.get_class_ci_total_count(clsurl)
    return({cmdb_class: ci_count})


process_results = [];
with ThreadPoolExecutor() as executor:
    for cmdb_class in cmdb_class_list:
        r = executor.submit(get_class_ci_count, cmdb_class, auth)
        process_results.append(r)

    for pr in as_completed(process_results):
        class_count.update(pr.result());

with open("ci_count.csv", "w") as cic:
    cic.write("class_name\tci_count\n")
    for k,v in sorted(class_count.items(), key=lambda item: item[1]):
        cic.write("{}\t{}\n".format(k,v))
