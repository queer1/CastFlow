class Carver
	@@klass_list = []
	@@klass = Hash.new do |hash,key|
		hash[key] = @@klass_list.find{|klass| klass.type_name == key}
	end
	def Carver.[](type_name)
		@@klass[type_name].new
	end
	def Carver.inherited(klass)
		@@klass_list << klass
	end
	def Carver.each(&block)
		@@klass_list.each(&block)
	end
	def carve(data)
		raise "Abstract class, please instantiate a concrete class"
	end
end

class Carvered
	attr_accessor :contentType ,:contentName ,:contentBody
	def initialize(cT, cN, cB)
		@contentType = cT
		@contentName = cN
		@contentBody = cB
	end
end
