from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.enableCli()

# Network definition
net.addP4Switch('s1', cli_input='s1-commands.txt')
net.addP4Switch('s2', cli_input='s2-commands.txt')
net.addP4Switch('s3', cli_input='s3-commands.txt')
net.addP4Switch('s4', cli_input='s4-commands.txt')
net.addP4Switch('s5', cli_input='s5-commands.txt')
net.addP4Switch('s6', cli_input='s6-commands.txt')
# Set P4 source files for each switch
net.setP4Source('s1', 'start_end.p4')
net.setP4Source('s2', 'middle.p4')
net.setP4Source('s3', 'middle.p4')
net.setP4Source('s4', 'middle.p4')
net.setP4Source('s5', 'middle.p4')
net.setP4Source('s6', 'start_end.p4')

net.addHost('h1')
net.addHost('h2')
# Add links
net.addLink('h1','s1')
net.addLink('s1', 's2')
net.addLink('s2', 's3')
net.addLink('s2', 's4')
net.addLink('s2', 's5')
net.addLink('s3', 's5')
net.addLink('s4', 's5')
net.addLink('s5', 's6')
net.addLink('h2','s6')
# Assignment strategy
net.mixed()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()

# Start network in a new thread
net.startNetwork()

