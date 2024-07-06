from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
#当然了，能顺利使用这个控制器的前提是你的机器上安装了p4 learning完备的开发环境
controller=SimpleSwitchThriftAPI(9090,thrift_ip='192.168.199.182')#9090端口代表目标BMV2实体开放的thrift接口（实际上就是TCP接口），thrift_ip代表BMV2交换机的IPv4地址
print(controller)
controller.table_add('dmac','forward',['00:00:0a:00:00:01'],['1'])
controller.table_add('dmac','forward',['00:00:0a:00:00:02'],['2'])
controller.table_add('dmac','forward',['00:00:0a:00:00:03'],['3'])
controller.table_add('dmac','forward',['00:00:0a:00:00:04'],['4'])
print('test succeed!!!')
