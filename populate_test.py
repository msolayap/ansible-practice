#populate_test.py


from snow_cmdb.populate import PopulateMysql

p = PopulateMysql(host='localhost',user='ansible', password='password231', database='lumen_snow_inventory')


dd = { 'sys_id': 'c7eeea431233f4910d2ce5355624vpk3d', 
'classname' : 'cmdb_ci_solaris_server', 
'x_ci_identifier' : '10.28.45.181', 
'category' : 'Hardware', 
'subcategory' : 'Computer', 
'classification' : 'Production',
'operational_status' : 1,
'install_status' : 1
     }


p.add_host('10.28.20.181', None, dd);



