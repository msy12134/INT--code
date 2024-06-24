import logging


def create_table(conn,cursor):
    cursor.execute("drop database if exists INTdata")
    cursor.execute("create database INTdata")
    cursor.execute("use INTdata")
    cursor.execute("""
        CREATE TABLE `links` (
          `link_id` int NOT NULL AUTO_INCREMENT,
          `switch_from_id` int NOT NULL,
          `switch_from_port` int NOT NULL,
          `switch_to_id` int NOT NULL,
          `switch_to_port` int NOT NULL,
          PRIMARY KEY (`link_id`)
        ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""")
    cursor.execute("""
        CREATE TABLE `intdata` (
          `link_id` int NOT NULL,
          `delay` float DEFAULT NULL,
          `throughput` float NOT NULL,
          `packet_loss` float NOT NULL,
          KEY `link_id` (`link_id`),
          CONSTRAINT `intdata_ibfk_1` FOREIGN KEY (`link_id`) REFERENCES `links` (`link_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""")
    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()
    logging.info("Databases:")
    for db in databases:
        if "intdata" in db:
            logging.info(db)

    cursor.execute("USE INTdata")
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    logging.info("Tables in INTdata:")
    for table in tables:
        if "intdata" in table or "links" in table:
            logging.info(table)
    conn.commit()


def deal_data(conn,cursor,list):
    for i in range(0,len(list)-1):
        switch_from_id=list[i].swid
        switch_from_port=list[i].egress_port
        switch_to_id=list[i+1].swid
        switch_to_port=list[i+1].ingress_port
        sql="select * from links where switch_from_id=%s and switch_from_port=%s and switch_to_id=%s and switch_to_port=%s"
        cursor.execute(sql,(switch_from_id,switch_from_port,switch_to_id,switch_to_port))
        result=cursor.fetchall()
        if len(result)==0:
            sql=("insert into links (switch_from_id, switch_from_port, switch_to_id, switch_to_port) VALUES "
                 "(%s,%s,%s,%s)")
            cursor.execute(sql,(switch_from_id,switch_from_port,switch_to_id,switch_to_port))
            conn.commit()
        delay=(list[i+1].ingress_cur_time-list[i].egress_cur_time)/1000
        throughtput=list[i].egress_byte_cnt/(list[i].egress_cur_time-list[i].egress_last_time)*1000000
        if list[i].egress_packet_count==0:
            packet_loss=0
        else:
            packet_loss=(list[i].egress_packet_count-list[i+1].ingress_packet_count)/list[i].egress_packet_count
        sql = "select link_id from links where switch_from_id=%s and switch_from_port=%s and switch_to_id=%s and switch_to_port=%s"
        cursor.execute(sql, (switch_from_id, switch_from_port, switch_to_id, switch_to_port))
        result = cursor.fetchone()
        if result:
            link_id = result[0]
            sql =("insert into intdata (link_id, delay, throughput, packet_loss) VALUES "
                  "(%s,%s,%s,%s)")
            cursor.execute(sql, (link_id, delay, throughtput, packet_loss))
            conn.commit()
