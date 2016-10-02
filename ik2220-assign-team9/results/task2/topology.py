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
        
	# firewall
	fw1 = self.addSwitch( 's2' )

	# private
        sw3 = self.addSwitch( 's3' )
        h3 = self.addHost( 'h3', ip='100.0.0.50/24' )
        h4 = self.addHost( 'h4', ip='100.0.0.51/24' )

        # public link
        self.addLink( h1, sw1 )
        self.addLink( h2, sw1 )

        # middle public
        self.addLink( fw1, sw1 )
        self.addLink( fw1, sw3 )

        # private link
        self.addLink( sw3, h3 )
        self.addLink( sw3, h4 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
