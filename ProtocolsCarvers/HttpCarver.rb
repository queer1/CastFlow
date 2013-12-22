require 'Carver'
require 'zlib'
require 'stringio'
require 'digest/md5'
require 'set'

# HTTP classes
## Global HTTP message
class HTTPMessage
	@@contentEncodings = Set["gzip", "deflate", "compress", "pack200-gzip", "identity"]
	@@transferEncodings = Set["chunked", "compress", "deflate", "gzip", "identity"]
	@@requestMethods = Set["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]	
	def HTTPMessage.contentEncodings() @@contentEncodings end
	def HTTPMessage.transferEncodings() @@transferEncodings end
	def HTTPMessage.requestMethods() @@requestMethods end

	attr_reader :headerFields ,:body
	def initialize()
		@headerFields = []
		@body = ""
	end

	def parseHeadersFrom(fData)
		fIndex = 0
		headersParsed = false
		
		fData.each do |line|
			if line.chomp.length > 0
				@headerFields << line.chomp
				fIndex += line.length
			else
				headersParsed = true
				fIndex += 2
				break
			end
		end
		
		@transferEncoding = getHeader("Transfer-Encoding")
		@contentEncoding = getHeader("Content-Encoding")
		@contentLength = getHeader("Content-Length")
		@contentType = getHeader("Content-Type")
			@contentType = "raw" unless @contentType
			@contentType = @contentType.split("/")[1] if @contentType
			@contentType = @contentType.split(";")[0] if @contentType and @contentType.index(";")
		return fData[fIndex...-1]
	end
	
	def getHeader(tag)
		@headerFields.each do |hdr|
			a = hdr.match(/#{tag}:\s+(.+)/)
			return a[1] if a
		end
		nil
	end	
	
	def parseBodyFrom(fData)
		decoded = fData
		garbage = 0
		decoded = Decoder.chunked(fData) if @transferEncoding == "chunked"
		if @transferEncoding == "chunked"
			garbage = fData[decoded.length...fData.length].index("\r\n0\r\n")
		end
		decoded = Decoder.deflate(fData) if @transferEncoding == "deflate"
		decoded = decoded[0,@contentLength.to_i] if (@contentLength and @contentLength.to_i > 0)
		decoded = Decoder.gzip(decoded) if @contentEncoding == "gzip"
		decoded = Decoder.deflate(decoded) if @contentEncoding == "deflate"
		@body = decoded
		garbage = 0 if not garbage
		garbage += 5 if garbage>0
		fData[@body.length+garbage...fData.length]
	end
end

## HTTP Request
class HTTPRequest < HTTPMessage
	attr_reader :requestMethod ,:fileURI
	def initialize()
		super()
	end
	def parseHeadersFrom(fData)
		data = super(fData)
		@requestMethod = @headerFields[0].split(" ")[0].split("/")[0]
		@fileURI = @headerFields[0].split(" ")[1]
		@headerFields.delete_at(0)
		data
	end
	# RFC 2616 sec 4.3
	def parseBodyFrom(fData)
		return fData if (not @transferEncoding) and (not @contentLength)
		return super(fData)
	end
end

## HTTP Response
class HTTPResponse < HTTPMessage
	attr_reader :body ,:contentType
	def initialize()
		super()
	end
	def parseHeadersFrom(fData)
		data = super(fData)
		@statusCode = @headerFields[0].split(" ")[1].to_i
		@headerFields.delete_at(0)
		data		
	end
	# RFC 2616 sec 4.3
	def parseBodyFrom(fData, request)
		return fData if request.requestMethod == "HEAD"
		return fData if (@statusCode >=100) and (@statusCode <=199)
		return fData if (@statusCode == 204) or (@statusCode == 304)
		return super(fData)
	end

end

### Content & Transfer Encodings decoder class
class Decoder
	def Decoder.chunked(content)
		data = content
		cSize = 1
		unchunked = ""
		while cSize != 0
			cInd = data.index("\r\n") # end of chunk size
			cSize = data[0,cInd].hex if cInd
			cSize = 0 unless cInd
			if cSize > 0
				data = data[cInd+2,data.length-1] # chunk start point
				unchunked << data[0,cSize] # chunk
				data = data[cSize+2,data.length-1]
			end
		end
		unchunked
	end
	def Decoder.gzip(content)
		gz = Zlib::GzipReader.new( StringIO.new( content ) ) 
		gz.read
	end
	def Decoder.deflate(content)
		Zlib::Inflate.inflate(content)
	end
end

class HttpCarver < Carver
	def HttpCarver.type_name
		"HTTP" 
	end
	def HttpCarver.contents
		@contents
	end
	def HttpCarver.carve(flow)
		@contents = []
		fData = flow.getFlowData()
		fIndex = 0
		while fData
			
			start_line = fData.split("\r\n")[0]
			return if not start_line
			return if start_line.length > 2048
			word = start_line.split(" ")[0].split("/")[0]
			return if (not HTTPMessage.requestMethods.include?(word)) and (word != "HTTP")
			mType = "RESPONSE" if word == "HTTP"
			mType = "REQUEST" if HTTPMessage.requestMethods.include?(word)
			if mType == "REQUEST"
				httpReq = HTTPRequest.new
				fData = httpReq.parseHeadersFrom(fData)
				fData = httpReq.parseBodyFrom(fData)
				if httpReq.body.length > 0
					cvd = Carvered.new(httpReq.contentType, httpReq.fileURI, httpReq.body)
					@contents << cvd
				end
			else
				httpResp = HTTPResponse.new
				fData = httpResp.parseHeadersFrom(fData)
				fData = httpResp.parseBodyFrom(fData, httpReq) if httpReq
				if httpResp.body.length > 0
					if httpResp.getHeader("Content-Disposition") # specified name
						fname = httpResp.getHeader("Content-Disposition").split(";")[1].split("=")[1]
					else # if not, request URI (by default xD)
						if httpReq
							fname = httpReq.fileURI.split("/")[-1].split("?")[0][0...12]
							fname = Digest::MD5.hexdigest(httpResp.body) if not fname.match(/[a-z]*[A-Z]*[.][a-z]*[A-Z]*/)
						else # either ? arfff!!... content MD5 hash so
							fname = Digest::MD5.hexdigest(httpResp.body)
						end
					end
					cvd = Carvered.new(httpResp.contentType, fname, httpResp.body)
					@contents << cvd
				end
			end
		end
	end
end
