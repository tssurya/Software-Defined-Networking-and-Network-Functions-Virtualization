#IK2220 SDN and NFV Assignment
#Team 9
#Authors: {atiiq,suryas,purwidi,mnde}@kth.se

"""
learning switch and firewall
References Used :
For Switch, 
1) the l2_learning-switch module in pox
For Firewall (in addition to the above),  
1) https://www.coursera.org/course/sdn1
2) http://kickstartsdn.com/
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
import time

from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet import *

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

flood_delay = 0
i = 0
#flag = 0

class LearningFirewall (EventMixin):
        def __init__(self,connection,transparent):
                # Switch we will be adding L2 learning switch capabilities to
                self.macToPort = {}
                self.connection = connection
                self.transparent = transparent
                self.listenTo(connection)
                self.firewall = {}
                self.flag = 0
        	self.hold_down_expired = flood_delay == 0
                self.stateful = {}
	def AddRule(self, dpidstr, dst = 0, dst_port = 0, value = True):
                self.firewall[(dpidstr, dst, dst_port, )] = value
                log.debug("Adding firewall rule in %s: %s %s", dpidstr, dst, dst_port)


        def CheckRule(self, dpidstr, dst = 0, dst_port = 0):
                try:
                        entry = self.firewall[(dpidstr, dst, dst_port)]
                        if(entry == True):
                                log.debug("Rule %s found in %s-%s:FORWARD", dst, dpidstr, dst_port)
                        else:
                                log.debug("Rule %s found in %s- %s:DROP", dst, dpidstr, dst_port)
                                return entry
                except KeyError:
                        log.debug("Rule %s NOT found in %s-%s: DROP", dst, dpidstr, dst_port)
                        return False

        def _handle_PacketIn (self, event):
                i = 0
                # parsing the input packet
                packet = event.parse()
                #self.stateful[i] = (packet.type, packet.src, event.port, packet.dst)
                #i = i+1
                def flood(message = None):
                        msg = of.ofp_packet_out()
                        if time.time() - self.connection.connect_time >= flood_delay:
                                if self.hold_down_expired is False:
                                        self.hold_down_expired = True
                                        log.info("%s: Flood hold-down expired -- flooding", event.dpid)
                                if message is not None:
                                        log.debug(message)
                                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                        else:
                                pass
                        msg.data = event.ofp
                        msg.in_port = event.port
                        self.connection.send(msg)
                def drop(duration = None):
                        if duration is not None:
                                if not isinstance(duration, tuple):
                                        duration = (duration, duration)
                                msg = of.ofp_flow_mod()
                                msg.match = of.ofp_match.from_packet(packet)
                                msg.idle_timeout = duration[0]
                                msg.hard_timeout = duration[1]
                                msg.buffer_id = event.ofp_buffer_id
                                self.connection.send(msg)
                        elif event.ofp.buffer_id is not None:
                                msg = of.ofp_packet_out()
                                msg.buffer_id = event.ofp.buffer_id
                                msg.in_port = event.port
                                self.connection.send(msg)

                # updating out mac to port mapping
                self.macToPort[packet.src] = event.port
                dpidstr = dpidToStr(event.connection.dpid)
                arp = packet.find('arp')
                if arp is not None:
			print "arp not none"
			#log.debug("%s"%arp.protodst)
			if arp.protodst == IPAddr('100.0.0.20') or arp.protodst == IPAddr('100.0.0.21') or arp.protodst == IPAddr('100.0.0.22') or arp.protodst == IPAddr('100.0.0.40') or arp.protodst == IPAddr('100.0.0.41') or arp.protodst == IPAddr('100.0.0.42') or arp.protodst == IPAddr('100.0.0.30'):
				print "Destination Host Unreachable"
				return
				
                ip = packet.find('ipv4')
                if ip is not None:
                        udp = ip.find('udp')
                        if udp is not None:
                                self.stateful[i] = (ip.id, ip.srcip, ip.dstip, udp.srcport,udp.dstport)
                                i = i+1
                                log.debug("this is udp protocol")
                                if self.CheckRule(dpidstr, packet.dst, udp.dstport) == False and self.CheckRule(dpidstr, packet.src, udp.srcport) == False:
                                        log.debug("the device is %s and the destination ip is %s-%s"%(dpidstr, packet.dst, udp.dstport))
                                        drop()
                                        self.flag = 1
                                        return

                        tcp = ip.find('tcp')
                        if tcp is not None:
                                self.stateful[i] = (ip.id, ip.srcip, ip.dstip, tcp.srcport,tcp.dstport)
                                i = i+1
                                log.debug("this is tcp protocol")

                                if self.CheckRule(dpidstr, packet.dst, tcp.dstport) == False and self.CheckRule(dpidstr, packet.src, tcp.srcport) == False:
                                        log.debug("the device is %s and the destination ip is %s-%s"%(dpidstr, packet.dst, tcp.dstport))
                                        drop()
                                        self.flag = 1
                                        return
                        icmp = ip.find('icmp')
                        if icmp is not None:
                                self.stateful[i] = (ip.id, ip.srcip, ip.dstip, icmp.code,icmp.type)
                                i = i+1
                                log.debug('icmp is not none %s' %icmp.type)
                                if self.CheckRule(dpidstr, packet.dst, icmp.type) == False:
                                        log.debug("the device is %s and the destination ip is %s-%s"%(dpidstr, packet.dst, icmp.type))
                                        drop()
                                        self.flag = 1
                                        return
                                                                                                                             
                else:
 #                               log.debug("this packet is not ip")
                                icmp = packet.find('icmp')
                                if icmp is not None:
                                        #self.stateful[i] = (icmp.type, icmp.srcip, icmp.dstip, udp.srcport,udp.dstport)
                                        i = i+1
                                        log.debug('icmp is not none %s' %icmp.type)
                                        if self.CheckRule(dpidstr, packet.dst, icmp.type) == False:
                                                log.debug("the device is %s and the destination ip is %s-%s"%(dpidstr, packet.dst, icmp.type))
                                                drop()
                                                self.flag = 1
                                                return 
#                                else:
#                                        log.debug("this packet is not icmp as well :(")
#					log.debug("%s"%packet.dst)
		#print "done"
		if self.flag == 1:
                        return
                if not self.transparent:
                        if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
                                drop()
                                return

                if packet.dst.is_multicast:
                        flood()
                else:
                        if packet.dst not in self.macToPort:
                                flood("Port for %s unknown --flooding" %(packet.dst,))
                        else:
                                # installing flow
                                outport = self.macToPort[packet.dst]
                                if outport == event.port:
                                        log.warning("Same port for packet from %s -> %s on %s. Drop." %
                                        (packet.src, packet.dst, outport), dpidToStr(event.dpid))
                                        return
                                log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, outport))
                                log.debug("this is dpid %s" % dpidToStr(event.dpid))
                                msg = of.ofp_flow_mod()
                                msg.match.dl_src = packet.src
                                msg.match.dl_dst = packet.dst
                                msg.idle_timeout = IDLE_TIMEOUT
                                msg.hard_timeout = HARD_TIMEOUT
                                msg.actions.append(of.ofp_action_output(port = outport))
                                msg.buffer_id = event.ofp.buffer_id
                                self.connection.send(msg)

class LearningFirewall1(LearningFirewall):
        def __init__(self,connection,transparent):
                LearningFirewall.__init__(self,connection,transparent)
                #rules for access to demilitarized zone and private zone:
                #Services accessible are a) dns server at 100.0.0.25:53 b) http server at 100.0.0.45:80 and c) icmp ping request and response to the virtual ip's of the servers 
                #dns and http server ping request,response      
                self.AddRule('00-00-00-00-00-02',EthAddr('0a:b9:f7:7e:59:6b'),8,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:02'),0,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('92:4a:f4:04:75:54'),8,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:01'),0,True)
                #rest generates icmp error if anything else if the DmZ is pinged

                #dns server udp query at port 53.
                self.AddRule('00-00-00-00-00-02',EthAddr('0a:b9:f7:7e:59:6b'), 53, True)

                #http server tcp query at port 80
                self.AddRule('00-00-00-00-00-02',EthAddr('92:4a:f4:04:75:54'),80,True)

                #host to host pinging
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:01'),8,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:02'),8,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('fa:dd:38:74:98:c8'),0,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('fa:dd:38:74:98:c8'),8,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:01'),0,True)
                self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:02'),0,True)

		self.AddRule('00-00-00-00-00-02',EthAddr('00:00:00:00:00:05'),8,False)
        def _handle_PacketIn (self, event):
                log.debug("I am inside Fw1")
                LearningFirewall._handle_PacketIn(self,event)

class LearningFirewall2(LearningFirewall):
        def __init__(self,connection,transparent):
                LearningFirewall.__init__(self,connection,transparent)
                #rules for access to demilitarized zone and private zone:
                #Services accessible are a) dns server at 100.0.0.25:53 b) http server at 100.0.0.45:80 and c) icmp ping request and response to the virtual ip's of the servers 
                #dns and http server ping request,response      
                self.AddRule('00-00-00-00-00-09',EthAddr('0a:b9:f7:7e:59:6b'),8,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('0a:b9:f7:7e:59:6b'),0,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('92:4a:f4:04:75:54'),8,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('92:4a:f4:04:75:54'),0,True)
                #rest generates icmp error if anything else if the DmZ is pinged

                #dns server udp query at port 53.
                self.AddRule('00-00-00-00-00-09',EthAddr('0a:b9:f7:7e:59:6b'), 53, True)

                #http server tcp query at port 80
                self.AddRule('00-00-00-00-00-09',EthAddr('92:4a:f4:04:75:54'),80,True)

                #host - to host ping
                self.AddRule('00-00-00-00-00-09',EthAddr('00:00:00:00:00:01'),8,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('00:00:00:00:00:02'),8,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('fa:dd:38:74:98:c8'),0,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('fa:dd:38:74:98:c8'),8,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('00:00:00:00:00:01'),0,True)
                self.AddRule('00-00-00-00-00-09',EthAddr('00:00:00:00:00:02'),0,True)

		self.AddRule('00-00-00-00-00-09',EthAddr('00:00:00:00:00:05'),8,False)
        def _handle_PacketIn (self, event):
                log.debug("I am inside Fw2")
                LearningFirewall._handle_PacketIn(self,event)

class LearningSwitch (EventMixin):
        def __init__ (self,connection):
                # Switch we will be adding L2 learning switch capabilities to
                self.macToPort = {}
                self.connection = connection
                self.listenTo(connection)

        def _handle_PacketIn (self, event):

                # parsing the input packet
                packet = event.parse()

                # updating out mac to port mapping
                self.macToPort[packet.src] = event.port

                if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
                        # Drop LLDP packets
                        # Drop IPv6 packets
                        # send of command without actions

                        msg = of.ofp_packet_out()
                        msg.buffer_id = event.ofp.buffer_id
                        msg.in_port = event.port
                        self.connection.send(msg)
                        return
                if packet.dst not in self.macToPort:
                        # does not know out port
                        # flood the packet
                        log.debug("I am inside the switch %s"% (event.dpid))
                        log.debug("Port for %s unknown -- flooding switch " % (packet.dst,))
                        msg = of.ofp_packet_out()
                        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                        msg.buffer_id = event.ofp.buffer_id
                        msg.in_port = event.port
                        self.connection.send(msg)
                        #log.debug("Still flooding")

                else:
                        # installing flow
                        outport = self.macToPort[packet.dst]
                        if outport == event.port:
                                log.warning("Same port for packet from %s -> %s on %s. Drop." %
                                (packet.src, packet.dst, outport), dpidToStr(event.dpid))
                                return
                        log.debug("installing flow for %s.%i -> %s.%i" % (packet.src, event.port, packet.dst, outport))
                        log.debug("this is dpid %s" % dpidToStr(event.dpid))
                        msg = of.ofp_flow_mod()
                        msg.match.dl_src = packet.src
                        msg.match.dl_dst = packet.dst
                        msg.idle_timeout = IDLE_TIMEOUT
                        msg.hard_timeout = HARD_TIMEOUT
                        msg.actions.append(of.ofp_action_output(port = outport))
                        msg.buffer_id = event.ofp.buffer_id
                        self.connection.send(msg)


class learning_switch (EventMixin):
        def __init__(self,transparent):
                self.listenTo(core.openflow)
                self.transparent = transparent

        def _handle_ConnectionUp (self, event):
                log.debug("Connection %s" % (event.connection,))
                if (event.dpid == 2 or event.dpid == 9):
                        log.debug("this is firewall triggered")
                        if (event.dpid ==2):
                                log.debug("I am inside firewall1")
				LearningFirewall1(event.connection,self.transparent)
				#LearningSwitch(event.connection)
                        else:
				log.debug("I am inside firewall2")
                                LearningFirewall2(event.connection,self.transparent)
				#LearningSwitch(event.connection)
                elif (event.dpid == 1 or event.dpid == 3 or event.dpid == 5 or event.dpid == 8 or event.dpid == 11):
                        log.debug("SWITCH triggered")
                        LearningSwitch(event.connection)
                else :
                        log.debug("CLICK triggered")
                        # DOING NOTHING

	def _handle_ConnectionDown(self,event):
		#ConnectionDown(event.connection,event.dpid)
        	log.info("Switch %s has shutdown.",dpidToStr(event.dpid)) 

def launch (transparent=False, hold_down = flood_delay):
        # Starts an L2 learning switch.
        try:
                global flood_delay
                flood_delay = int(str(hold_down),10)
                assert flood_delay >=0
        except:
                raise RuntimeError("Expected hold-down to be a number")
        core.registerNew(learning_switch, str_to_bool(transparent))


