
from abc import ABC, abstractmethod, abstractproperty
import pymysql

class Populate(ABC):
    """abstract class that defines the interface for various data populate methods.
    The idea is to have a flexible data store architecture, so that interface remains
    same in the top level, but underlying implementation of host/group data store is different.

    """
    def __init__(self):
        pass

    @abstractmethod
    def add_host(self, hostname, groupname=None, host_data=dict()):
        pass

    def add_group(self, groupname, parent_group=None):
        pass

class PopulateMysql(Populate):
    """sub class of Populate. Pushes Inventory data to mysql/mariadb database table
    table structure, field names are predefined and agreed. 
    
    
    """
    def __init__(self, **kwargs):
        """initialize the instance
        connect to database. 

        parameters:
        host - database hostname
        user - database user
        password - database password
        database - database to connect to
        """
        self.host = host 
        self.user = user
        self.password = password
        self.database = database
        try:

            self.connect_to_db();
        
        except Exception as e:
            
            print(e)

        
    def add_host(self, hostname, groupname,  host_data):
        """method to handle the incoming record and populate
        to mysql table appropriately.

        hostname - the primary name to address the CI
        groupname - groupname this host needs to go.
        host_data - dict contains various attributes of the host. eventually
                    each key will be a host variable
        """
        try:

            tablename = "cmdb_ci_details"

            if(not self.conn.open):
                print("DB connection closed")

            stmt = """INSERT INTO {} (sys_id, classname, x_ci_identifier, category, subcategory, classification, operational_status, install_status)    VALUES ( '%s', '%s', '%s', '%s', '%s', '%s', %d, %d ) """.format(tablename)
            stmt_args = (
                host_data.get('sys_id'),
                host_data.get('sys_class_name', ''),
                host_data.get('x_ci_identifier'),
                host_data.get('category','generic_ci'),
                host_data.get('subcategory',''),
                host_data.get('classification','default'),
                host_data.get('operational_status',0),
                host_data.get('install_status',0)
            )
            
            cursor = self.conn.cursor()
            
            cursor.execute(stmt, stmt_args)

            self.conn.commit();
             
        except Exception as e:
            
            print("Exception while adding host record", e)
        

    def connect_to_db(self):
        
        self.conn = None
        c = pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database
        )
        self.conn = c
        
    def add_group(self, groupname, parent_group=None):
        pass

