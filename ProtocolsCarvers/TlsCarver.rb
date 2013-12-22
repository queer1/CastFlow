require 'Carver'
require 'openssl'

class TLSMessage
	attr_reader :mType ,:mLength ,:mData
	def initialize(data)
		@mType   = data[0].to_s(16)
		@mLength = (data[1].to_s(16).rjust(2,'0') + data[2].to_s(16).rjust(2,'0') + data[3].to_s(16).rjust(2,'0')).hex
		@mData   = data[4, @mLength]
	end
end

class TLSCertificate < TLSMessage
	def populate()
		certs = []
		@cLength = (@mData[0].to_s(16).rjust(2,'0') + @mData[1].to_s(16).rjust(2,'0') + @mData[2].to_s(16).rjust(2,'0')).hex
		@cData   = @mData[3, @cLength]
		idx = 0
		while idx < @cLength
			len = (@cData[idx].to_s(16).rjust(2,'0') + @cData[idx+1].to_s(16).rjust(2,'0') + @cData[idx+2].to_s(16).rjust(2,'0')).hex
			idx += 3
			crt = OpenSSL::X509::Certificate.new(@cData[idx, len])
			certs[certs.length] = crt
			idx += len
		end
		certs
	end
end

class TLSRecord
	attr_reader :rType ,:rLength ,:rData ,:certs
	def initialize(data)
		@rType = data[0].to_s(16)
		@rLength = (data[3].to_s(16).rjust(2,'0') + data[4].to_s(16).rjust(2,'0')).hex
		@rData = data[5, @rLength]
		@certs = []
	end
	def populate()
		tlsMessageHeaderLength = 4 # type+length=4 bytes length 
		mIdx = 0
		while mIdx+tlsMessageHeaderLength <= @rLength
			message = TLSMessage.new(@rData[mIdx,@rData.length])
			if message.mType == "b" #0x0b == certificate message
				a = TLSCertificate.new(@rData[mIdx,@rData.length])
				@certs += a.populate
			end
			mIdx = mIdx + tlsMessageHeaderLength + message.mLength
		end
	end
end

class TlsCarver < Carver
	def TlsCarver.type_name
		"TLS"
	end
	def TlsCarver.contents
		@contents
	end
	def TlsCarver.carve(flow)
		data = flow.getFlowData
		@contents = []
		# TLS Certificates extraction
		rIdx = 0
		while rIdx < data.length
			record = TLSRecord.new(data[rIdx, data.length])
			record.populate
			if record.rType == "16" # handshake protocol
				record.certs.each do |cert|
					cvd = Carvered.new("x509-Certificate", Digest::MD5.hexdigest(cert.to_s) + ".x509-Certificate", cert.to_s)
					@contents[@contents.length] = cvd
				end
			end
			rIdx = rIdx + record.rLength + 5 # type+version+length=5 bytes length
		end
	end
end
