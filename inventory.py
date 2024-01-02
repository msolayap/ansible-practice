import time
import logging
import atexit
import pymysql 
import sys 

from pprint import pprint

from snow_cmdb.oauthclient import CredentialsStoreVault, SnowApiAuth, SnowCmdbApi

## main code

base_dir="/data01/home/ansible/ansible-practice/"
vault_file          = base_dir + "/vault_lumen_snow"
vault_password_file = base_dir + "/vault_password_file" ;
cmdb_class_config = {
    'cmdb_ci_unix_server': {
        'groupname' : 'servers',
        'req_attribs' : [
            'sys_id',
            'sys_class_name',
            'category',
            'subcategory',
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

snow_api = SnowCmdbApi('lumen', auth, page_limit=dev_page_limit, test_ci_count=dev_total_count)


host_count = 0
ci_details = [];
results = []

db_conn = pymysql.connect(host=db_config['host'],
        user=db_config['user'],
        password=db_config['password'],
        database=db_config['database']
        );

if(db_conn.open):
    print("Connected to database ... ")
    print("deleting existing records...");
    db_conn.cursor().execute("delete from cmdb_ci_details");
    db_conn.commit()
else:
    print("Couldn't connect to database. exiting");
    sys.exit(1);
        
inventory_table = 'cmdb_ci_details'

for cmdb_class in cmdb_class_config:

    for ci_list in snow_api.get_class_ci_list(cmdb_class):

        for ci_id in ci_list:

            ci_detail = snow_api.get_ci_details(cmdb_class, ci_id, cmdb_class_config[cmdb_class])

            if( 'sys_id' in ci_detail ):
                print("inserting ci %s" % (ci_detail['x_ci_identifier']))

                stmt = """INSERT INTO %s (sys_id, classname, x_ci_identifier, category, subcategory, classification, operational_status, install_status ) values ( '%s', '%s', '%s', '%s', '%s', '%s', %d, %d )""" % (
                    inventory_table,
                    ci_detail['sys_id'],
                    ci_detail['sys_class_name'],
                    ci_detail['x_ci_identifier'],
                    ci_detail['category'],
                    ci_detail['subcategory'],
                    ci_detail['classification'],
                    int(ci_detail.get('operational_status',0)),
                    int(ci_detail.get('install_status', 0))
                    )
                db_conn.cursor().execute(stmt)



db_conn.commit()
print("Commited all records");

                

