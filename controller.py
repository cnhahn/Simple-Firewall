# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

#rules we need to implement
#----------------------------------------------------------
#src ip       | dst ip       | protocol    | action
#----------------------------------------------------------
#any          | any          | icmp        | accept
#any          | any          | arp         | accept
#10.0.1.10(h1)| 10.0.1.30(h3)| tcp         | accept
#10.0.1.30(h3)| 10.0.1.10(h1)| tcp         | accept
#any          | any          | -           | drop

  def do_firewall (self, packet, packet_in):
    
    print "Entered do_firewall"

    
    #create a table to install ARP, TCP, and ICMP rules
    table = of.ofp_flow_mod()
    table.match = of.ofp_match.from_packet(packet)

    #set some timers for timeout and idle spefically for incoming packets
    table.idle_timeout = 25
    table.hard_timeout = 80
    
    print "make if statements"
      
    TCP = packet.find('tcp')
    if TCP is not None:
      print "TCP is not none"
      
      ipv4 = packet.find('ipv4')

      src_ip = ipv4.srcip
      dst_ip = ipv4.dstip
      
      print src_ip
      print dst_ip

      #table.match.tp_src = src_ip
      #table.match.tp_dst = dst_ip

      #print table.match.tp_src
      #print table.match.tp_dst

      if (src_ip == "10.0.1.10" and dst_ip == "10.0.1.30") or (src_ip == "10.0.1.30" and dst_ip == "10.0.1.10"):
      #if table.match.tp_src == "10.0.1.10" and table.match.tp_dst == "10.0.1.30":
     
        print "found the correct src and dst ips"
        #table.match.nw_src = src_ip
        #table.match.nw_dst = dst_ip
       
        #msg = of.ofp_flow_mod()
        #msg.data = packet_in
        
        table = of.ofp_flow_mod()
        table.data = packet_in
        
        #get to this place because of the of the defined filter we applied with checks. then at this line below that all the infomation must match this packet.
        #this is what allows us to check and verify that our packets coming in are correct.
        
        #msg.match = of.ofp_match.from_packet(packet)
        table.match = of.ofp_match.from_packet(packet)

        #table.match.nw_src = "10.0.1.10"
        #table.match.nw_dst = "10.0.1.30"
        #table.match.nw_proto = 6

        # look at what fields i can match
        #table.data = packet_in
        action_TCP = of.ofp_action_output(port = of.OFPP_FLOOD)
        table.actions.append(action_TCP)
        #msg.actions.append(action_TCP)
        self.connection.send(table)
        
      else:
        
        print "did not find the correct src and dst ips"
        self.connection.send(table)
        

    else:
      print "TCP is none"
      table.data = packet_in
        
      ICMP = packet.find('icmp')

      if ICMP is not None:
        print "ICMP is not none"
        #table.data = packet_in
        table.match.nw_proto = 1
        table.data = packet_in
        action_ICMP = of.ofp_action_output(port = of.OFPP_FLOOD)
        table.actions.append(action_ICMP)
        self.connection.send(table)

      else:
        print "ICMP is none"
        table.data = packet_in
          
        ARP = packet.find('arp')
        if ARP is not None:
          print "ARP is not none"
          #table.data = packet_in
          table.match.dl_type = 0x0806
          table.data = packet_in
          action_ARP = of.ofp_action_output(port = of.OFPP_FLOOD)
          table.actions.append(action_ARP)
          self.connection.send(table)
        else:
          print "ARP is none"
          table.data = packet_in 
          

    print "end of all checks---------------------"

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
