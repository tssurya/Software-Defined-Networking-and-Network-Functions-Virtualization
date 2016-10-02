# ====================================
# Task1 Topology
# Team 9
# ====================================

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        # public zone
        sw1 = self.addSwitch( 's1' )
        h1 = self.addHost( 'h1', ip='100.0.0.10/24' )
        h2 = self.addHost( 'h2', ip='100.0.0.11/24' )
        fw1 = self.addSwitch( 's2' )

        # public link
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
