from mininet.topo import Topo

class DataCenterTopo(Topo):
    """
    Simple Data Center Topology

    linkopts - list of link options for each layer [core, aggregation, edges]
    depth    - number of layers
    fanout   - number of child switch per parent switch
    """
    def __init__(self, linkopts, depth=3, fanout=2, **opts):
        
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switches = {} # {depth level: list of nodes}
        hosts = []

        # Add core switch 
        switches[0] = list() 
        switches[0].append(self.addSwitch('s1')) 

        # Build aggregation and edge layers 
        for s in range(1, depth): 
            switches[s] = list() 
            for sw in range(0,fanout**s):
                switch_id = fanout**s+sw
                switches[s].append(self.addSwitch('s%s'%(switch_id)))
                self.addLink(switches[s][-1],switches[s-1][sw//fanout], **linkopts[s-1])

        # Add hosts
        for h in range(0, fanout**depth):
            hosts.append(self.addHost('h%s'%(h+1)))
            self.addLink(hosts[-1],switches[depth-1][h//fanout], **linkopts[2])


# List of link options for each layer
linkopts = [
    {'bw':10, 'delay':'5ms', 'loss':1, 'max_queue_size':1000, 'use_htb':True},   # core–agg
    {'bw':5,  'delay':'10ms', 'loss':2, 'max_queue_size':500,  'use_htb':True},  # agg-–edge
    {'bw':1,  'delay':'20ms', 'loss':5, 'max_queue_size':100,  'use_htb':True},  # edge–host
]

topos = { 'datacenter': ( lambda: DataCenterTopo(linkopts, depth=3, fanout=2) ) }
