


import pymysql


connection = pymysql.connect(host='localhost',
        user='ansible',
        password='password231',
        database='lumen_snow_inventory'
        );

if(connection.open):
    print("Connected to database ... ");

with connection:
    with connection.cursor() as cursor:
        cursor.execute('delete from cmdb_ci_details');
        with open('ins.sql', 'r') as sql_stmt:
            for stmt in sql_stmt:
                cursor.execute(stmt)

    connection.commit()

