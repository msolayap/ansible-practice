import time
import logging
import atexit
import sys 

from pprint import pprint

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowTableApi, SnowCmdbCIGenericParser
from snow_cmdb.populate import PopulateMysql

## main code

base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;
cmdb_class_config = {
    'cmdb_ci_win_server': {
        'groupname' : 'servers',
        'req_attribs' : [
            'sys_id',
            'sys_class_name',
            'category',
            'subcategory',
            'name',
            'operational_status',
            'install_status',
            'classification',
            'os'
        ],
        'hostname_scan_order': ['ip_address','fqdn','name','host_name']
    },
    'cmdb_ci_linux_server': {
        'groupname' : 'servers',
        'req_attribs' : [
            'sys_id',
            'sys_class_name',
            'category',
            'subcategory',
            'name',
            'operational_status',
            'install_status',
            'classification',
            'os'
        ],
        'hostname_scan_order': ['ip_address','fqdn','name','host_name']
        
    }
}

db_config = {
        'host' : 'localhost',
        'user' : 'ansible',
        'password' : 'password231',
        'database': 'lumen_snow_inventory'
        }

start = time.time();

def end_tasks():
    end = time.time();
    exec_time = round((end - start), 2)
    print("\nFinished in -> {:.2f} seconds".format(exec_time), file=sys.stderr)
    print ("{} CMDB Classes processed".format(cc), file=sys.stderr)
    print("{} CIs Processed\n{} CIs Added".format(pc, ac), file=sys.stderr);
    print("{} Cis processed per second".format(round(pc/exec_time,2)), file=sys.stderr);

atexit.register(end_tasks)

#### logger ###

#logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.WARNING, datefmt='%Y-%m-%d-%H:%M:%S');

#logger = logging.getlogger("__name__")

#logger.setLevel(logging.DEBUG)
#fh = logging.StreamHandler();
#fh.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d-%H:%M:%S')
#fh.setFormatter(formatter);
#logger.addHandler(fh)

dev_page_limit = 1000
dev_total_count = 0


credstore = CredentialsStoreVault(vault_file, vault_password_file);

auth = SnowApiAuth( credstore.get_credentials() );

auth.refresh_token();


snow_api = SnowTableApi('lumen', auth, page_limit=dev_page_limit, test_ci_count=dev_total_count)

host_count = 0
ci_details = [];
results = []

populate = PopulateMysql(host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database']
        );

pc=0
ac=0
pps=0
cc=0

ci_parser = SnowCmdbCIGenericParser();

for cmdb_class in cmdb_class_config:
    cc += 1

    for ci_list in snow_api.get_ci_list(cmdb_class):

        for ci_data in ci_list:
            pc += 1

            ci_parser.ci_details = ci_data
            ci_detail = ci_parser.filter_ci_record(cmdb_class_config[cmdb_class])

            if( ci_detail ):
                ac += 1
                print("inserting ci %s" % (ci_detail['x_ci_identifier']))
                hostname = ci_detail['x_ci_identifier'] 
                #pprint(ci_detail);

                populate.add_host(hostname, None, ci_detail)


print("Commited all records");

                

