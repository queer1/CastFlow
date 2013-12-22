#!/usr/bin/ruby

require 'packetfu'
require 'digest/md5'
require 'fileutils'
require 'optparse'

class PacketCapturer
	attr_reader :reader
	def initialize(evidence)
		evidence = File.open(evidence) {|f| f.read}
		@reader = PacketFu::PcapPackets.new
		@reader.read(evidence)
	end
	def FullRead(callback)
		@reader.each { |p|
			ts = p.timestamp.sec.to_i.to_s + "." + p.timestamp.usec.to_i.to_s
			# strip => true to cut off eth frame trailers
			packet = PacketFu::Packet::parse(p.data, :strip => true)
			callback.call(ts, packet)
		}
	end
end

class FlowGenerator
	attr_reader :store
	def initialize()
		@store = {}
	end
	def existFlow(hash)
		@store.has_key?(hash)
	end
	def updateEntry(ts, pkt)
		hash = Flow.new(ts,pkt).getHash()
		if not existFlow(hash) # new flow
			fl = Flow.new(ts, pkt)
			@store[hash] = fl
		else # update existing flow
			@store[hash].updateEntry(ts, pkt)
		end
	end
	# packetcapturer pcap callback method
	def ProcessPacket(ts, pkt)
		if pkt.is_tcp? or pkt.is_udp?
			updateEntry(ts,pkt)
		end
	end
	def run(fname)
		pc = PacketCapturer.new(fname)
		pc.FullRead(method(:ProcessPacket))
	end
	def getValues()
		@store.values
	end
end

class Flow
	attr_reader :StartTime, :EndTime, :TotalBytesInFlow
	attr_reader	:SourceAddress, :SourceService
	attr_reader	:DestinationAddress, :DestinationService
	attr_reader :Packets
	attr_accessor :Protocol
	def initialize(ts, data)
		@StartTime          = ts
		@EndTime            = nil
		@SourceAddress      = nil
		@SourceService      = nil
		@DestinationAddress = nil
		@DestinationService = nil
		@Protocol           = nil
		@TotalBytesInFlow   = 0
		@Packets            = []
		@Hash               = nil
		updateEntry(ts, data)
	end
	def updateEntry(ts, pkt)
		@EndTime            = ts
		if not @Hash
			@SourceAddress      = pkt.ip_saddr
			@DestinationAddress = pkt.ip_daddr
			if pkt.is_tcp?
				@SourceService      = pkt.tcp_sport
				@DestinationService = pkt.tcp_dport
			elsif pkt.is_udp?
				@SourceService      = pkt.udp_sport
				@DestinationService = pkt.udp_dport		
			end
		end
		@TotalBytesInFlow  += pkt.payload.length
		@Hash               = getHash()
		@Packets << [ts,pkt]
	end
	def getFlowData()
		fData = ""
		@Packets.each do |p|
			if fData.index(p[1].payload) == nil
				fData << p[1].payload
			end
		end
		fData
	end
	
	def getHash()
		src = Digest::MD5.hexdigest(@SourceAddress.to_s+@SourceService.to_s)
		dst = Digest::MD5.hexdigest(@DestinationAddress.to_s+@DestinationService.to_s)
		(src.hash ^ dst.hash)
	end
	def getDescription()
		@SourceAddress.to_s + "." + @SourceService.to_s + "_" + @DestinationAddress.to_s + "." + @DestinationService.to_s
	end
	def to_f(dir)
		desc = getDescription
		@Packets.each do |pkt|
			pkt.to_f(dir+"/"+desc+".dump", "a")
		end
	end
	def to_s()
		"#{@StartTime} - #{@EndTime} | #{@SourceAddress}:#{@SourceService} > #{@DestinationAddress}:#{@DestinationService} Packets(#{@Packets.length}) Bytes(#{@TotalBytesInFlow})"
	end
end

class FlowPL7Identificator
	def findProtocols(srcPort, dstPort)
		coincidences = []
		coincidences.push("HTTP") if ((dstPort == 80) or (dstPort == 8080) or srcPort == 80 or srcPort == 8080)
		coincidences.push("NBNS") if ((dstPort == 137) or (srcPort == 137))
		coincidences.push("TLS") if ((dstPort == 443) or (dstPort == 465) or (dstPort == 563) or (dstPort == 992) or (dstPort == 993) or 
								     (dstPort == 994) or (dstPort == 995) or (dstPort == 989) or (dstPort == 990) or (srcPort == 443) or 
									 (srcPort == 465) or (srcPort == 563) or (srcPort == 992) or (srcPort == 993) or (srcPort == 994) or 
									 (srcPort == 995) or (srcPort == 989) or (srcPort == 990)) 
		coincidences.push("OSCAR-FT") if ((dstPort == 443) or (dstPort == 5190) or (srcPort == 443) or (srcPort == 5190))
		coincidences
	end
end

class DynCarversLoad
	def initialize(basedir)
		@basedir = basedir
	end
	def parse()
		Dir.glob(@basedir+"*.rb").each do |path|
			require "#{path}"
		end
	end
end


## Main process

options = {}
optparse = OptionParser.new do|opts|
	opts.banner = "Usage: castflow.rb [options] Evidence_PCAP_File"

	opts.on( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end

	options[:evidence] = nil
	opts.on( '-r', '--read FILE', 'Read packets from FILE' ) do|fil|
		raise Exception.new("#{fil} does not exist.") unless File.exist?(fil)
		options[:evidence] = fil
	end	
end

optparse.parse!
raise Exception.new("Need a evidence infile: Use option -r/--read") if not options[:evidence]

tm = Time.now.to_s
dumpdir = "FilesCarvered on #{tm}"

raise Exception.new("#{dumpdir} directory already exist.") if File.directory?(dumpdir)
begin
	Dir.mkdir(dumpdir)
rescue SystemCallError
	$stderr.print "IO failed" + $!
	raise
end

title = "Forensics pcap File Carving in '#{options[:evidence]}'"
puts title
puts "-" * title.size

puts "[i] Loading Protocols Carvers modules"
cvss = DynCarversLoad.new("ProtocolsCarvers/")
cvss.parse()

fg = FlowGenerator.new()
puts "[i] Grouping packets in flows from #{options[:evidence]}"
fg.run(options[:evidence])
fg.getValues().each do |flow|
	pdpi = FlowPL7Identificator.new()
	pdpi.findProtocols(flow.SourceService, flow.DestinationService).each do |probProt|
		if not flow.Protocol
			Carver.each do |carverKlass|
				if (carverKlass.type_name == probProt)
					begin
						carverKlass.carve(flow)
						carverKlass.contents.each do |content|
							nFile = 2
							fname = dumpdir+"/"+content.contentName+"."+content.contentType
							while File.exist?(fname)
								fname = dumpdir+"/"+content.contentName+"(" + nFile.to_s() +")."+content.contentType							
								nFile += 1
							end
							aFile = File.new(fname, "wb")
							aFile.write(content.contentBody)
							aFile.close
							flow.Protocol = probProt
							puts "\tCarvered #{content.contentName} file (#{content.contentType}) with #{ Digest::MD5.hexdigest(content.contentBody)} MD5 hash."
						end
					rescue Exception => e
						#puts e.message
						#puts e.backtrace.inspect 
						# nothing to do here
					end
				end
			end
		end
	end
end
