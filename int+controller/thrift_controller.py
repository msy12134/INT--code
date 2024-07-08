import pymysql
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import threading
import time

# 初始化 SimpleSwitchThriftAPI 控制器
controller1 = SimpleSwitchThriftAPI(9090, thrift_ip='127.0.0.1')
controller4 = SimpleSwitchThriftAPI(9093, thrift_ip='127.0.0.1')
if controller1 and controller4:
    print("The connection of s1 and s4 is established!!!")

# 初始化数据库连接函数
def create_db_connection():
    return pymysql.connect(
        unix_socket="/var/run/mysqld/mysqld.sock"
    )

# 初始化全局变量
link_delay_1 = None
link_delay_2 = None
link_delay_3 = None
link_delay_4 = None
link_delay_5 = None
link_delay_6 = None

def fetch_delays():
    global link_delay_1, link_delay_2, link_delay_3, link_delay_4, link_delay_5, link_delay_6
    # 每次查询时创建新的数据库连接
    connection = create_db_connection()
    with connection.cursor() as cursor:
        sql = "SELECT * FROM INTdata.intdata"
        cursor.execute(sql)
        result = cursor.fetchall()
        if result:
            link_delay_1 = result[0][1]
            link_delay_2 = result[1][1]
            link_delay_3 = result[2][1]
            link_delay_4 = result[3][1]
            link_delay_5 = result[4][1]
            link_delay_6 = result[5][1]
            print(f"Fetched delays: {link_delay_1}, {link_delay_2}, {link_delay_3}, {link_delay_4}, {link_delay_5}, {link_delay_6}")
    connection.close()

def periodically_fetch(interval):
    while True:
        fetch_delays()
        time.sleep(interval)

# 创建并启动线程
t1 = threading.Thread(target=periodically_fetch, args=(1,))
t1.start()

# 主循环中检查全局变量是否已被赋值
while True:
    if None not in [link_delay_1, link_delay_2, link_delay_3, link_delay_4, link_delay_5, link_delay_6]:
        delay_of_route1 = link_delay_1 + link_delay_6
        delay_of_route2 = link_delay_5
        delay_of_route3 = link_delay_3 + link_delay_4
        if delay_of_route1 < delay_of_route2 and delay_of_route1 < delay_of_route3:
            controller1.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.4.2'], ['00:00:00:00:00:01','2'])
            controller4.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.1.1'], ['00:00:00:00:00:02','2'])
            print('Choose route1')
        elif delay_of_route2 < delay_of_route1 and delay_of_route2 < delay_of_route3:
            controller1.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.4.2'], ['00:00:00:00:00:01','4'])
            controller4.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.1.1'], ['00:00:00:00:00:02','1'])
            print('Choose route2')
        elif delay_of_route3 < delay_of_route1 and delay_of_route3 < delay_of_route2:
            controller1.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.4.2'], ['00:00:00:00:00:01','3'])
            controller4.table_modify_match('ipv4_lpm', 'ipv4_forward', ['10.0.1.1'], ['00:00:00:00:00:02','3'])
            print('Choose route3')
    else:
        print("Waiting for delay data...")
    time.sleep(1)
