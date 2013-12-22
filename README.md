CastFlow
========

Forensics pcap File Carving.


Description: 

1. q.jar & sdfg.jar
2. ADMINISTRATOR
3. http://nrtjo.eu/true.php
4. 5942ba36cf732097479c51986eee91ed
5. UPX
6. 0f37839f48f7fc77e6d50e14657fb96e
7. 213.155.29.144

Throughout the analysis process, I will work all the time with files extracted from infected.pcap evidence file.

Therefore, first step is extract evidence file contents. We have tons of tools to do this, but I miss some 
portable/modular PCAP File Extraction Framework(maybe this kind of tool exists and I don't know), so I have
tried to make one.

After content extraction, we have this:

	foo-mac:puzzle5 edelfa$ ./castflow.rb -r infected.pcap 
	Forensics pcap File Carving in 'infected.pcap'
	[i] Loading Protocols Carvers modules
	[i] Grouping packets in flows from infected.pcap
		Carvered file.exe file (octet-stream) with 5942ba36cf732097479c51986eee91ed MD5 hash.
		Carvered sdfg.jar file (x-java-archive) with cb0b060aef8cb1b70074ce25e25f5abd MD5 hash.
		Carvered favicon.ico file (html) with ce0b699890509fa13e0b30769a5ca610 MD5 hash.
		Carvered gate.php file (html) with f149dcbc17a40eaa1ebce64d48169cf8 MD5 hash.
		Carvered true.php file (html) with 72af7c4d94974fe7ca006b670d30fe95 MD5 hash.
		Carvered file.exe file (octet-stream) with 5942ba36cf732097479c51986eee91ed MD5 hash.
		Carvered q.jar file (x-java-archive) with ee55192bd3237e8f10565b1d0605af2e MD5 hash.
		Carvered a7f4f9d34b2e56e6f4e279b07466ad44.x509-Certificate file (x509-Certificate) with a7f4f9d34b2e56e6f4e279b07466ad44 MD5 hash.
		Carvered 901436e235a81e2ac977ff04b582e518.x509-Certificate file (x509-Certificate) with 901436e235a81e2ac977ff04b582e518 MD5 hash.
		Carvered 1f1804ae8a54aab57f746237a6c121c1.x509-Certificate file (x509-Certificate) with 1f1804ae8a54aab57f746237a6c121c1 MD5 hash.

At this point, question one is answered: q.jar and sdfg.jar

	foo-mac:FilesCarvered on Sat May 15 02:39:13 +0200 2010 edelfa$ file *.*x-java-archive
	q.jar.x-java-archive:    Zip archive data, at least v2.0 to extract
	sdfg.jar.x-java-archive: Zip archive data, at least v1.0 to extract

We also can see two windows executables:

	foo-mac:FilesCarvered on Sat May 15 02:39:13 +0200 2010 edelfa$ file file*.*stream
	file.exe(2).octet-stream: MS-DOS executable PE  for MS Windows (GUI) Intel 80386 32-bit, UPX compressed
	file.exe.octet-stream:    MS-DOS executable PE  for MS Windows (GUI) Intel 80386 32-bit, UPX compressed

Both of them seems to be the same file, and we can see that they are packet with UPX packet.

	foo-mac:FilesCarvered on Sat May 15 02:39:13 +0200 2010 edelfa$ upx -d -o file_decompressed.exe file.exe.octet-stream 
        	               Ultimate Packer for eXecutables
        	                  Copyright (C) 1996 - 2008
	UPX 3.03        Markus Oberhumer, Laszlo Molnar & John Reiser   Apr 27th 2008

		        File size         Ratio      Format      Name
		   --------------------   ------   -----------   -----------
		     82432 <-     68096   82.61%    win32/pe     file_decompressed.exe
		
		Unpacked 1 file.
		
	foo-mac:FilesCarvered on Sat May 15 02:39:13 +0200 2010 edelfa$ file file_decompressed.exe 
		file_decompressed.exe: MS-DOS executable PE  for MS Windows (GUI) Intel 80386 32-bit

	foo-mac:FilesCarvered on Sat May 15 02:39:13 +0200 2010 edelfa$ md5 file_decompressed.exe 
		MD5 (file_decompressed.exe) = 0f37839f48f7fc77e6d50e14657fb96e

At this point, questions 4, 5 and 6 are answered:

	Packed file MD5 hash: 5942ba36cf732097479c51986eee91ed
	Packer: UPX
	Unpacked file MD5 hash: 0f37839f48f7fc77e6d50e14657fb96e

As to the infection starting point (URL), analizing infected.pcap file with Wireshark tool, we can see that, the first HTTP request with 59.53.91.102 as IP destination address is asking for /true.php resource and into previous frames to this HTTP request, we have one DNS query/response pair that resolves this address as nrtjo.eu, so this incident start by clicking on http://nrtjo.eu/true.php link, so this is the answer to the question 3.

Questions 2 and 7 has a similar resolution, and at this point seems clear that the infected system username is ADMINISTRATOR and hard-coded IP address is 213.155.29.144, but I will try to prove it.

For these data, first I launch a sniffer in one hand, and malware piece in the other hand.
We can see that it has tried to resolve freeways.in domain with no answer, and has tried to connect with 213.155.29.144 address on 444 service, with no answer again.

We are on track. Now with some funny cheats, we will try that this time "he" be able to resolve freeways.in domain, and connect to this IP address (or at least that he believe that does both).

	We need to take this steps.
		1.- Setup our network connection with 127.0.0.1 as DNS server.
		2.- ADD new IP address to our network interface (before: 192.168.2.13, After: 192.168.2.13 and 213.155.29.144 "multiple IP address").
		3.- Add new route: route ADD 213.155.29.144 MASK 255.255.255.255 192.168.2.13
		4.- Launch FakeDNS
		5.- Launch netcat to listen on 80 and 444 local ports (nc.exe -l -p 80 and nc.exe -l -p 444)
		6.- Launc WinDump.exe -w somefilename.pcap
		7.- Launc file.exe (from cleaned system)

And finally, we receive our desired HTTP request, and our hard-coded connection too.
GET /11111/gate.php?guid=MRMONEYFEW!ED-PUZZLE5-LAB!DC11E3C&ver=1008&stat=ONLINE&ie=6.0.3790.395&os=5.2.3790&ut=Admin&cpu=17&ccrc=5A4F4DF7&MD5=0f37839f48f7fc77e6d50e14657fb96e

MRMONEYFEW is my username on the lab system, so ADMINISTRATOR is the username on Ms MoneyMany system.

And we have received one connection to 444 port without DNS usage, so again, 213.155.29.144 is the hard-coded IP address.

Ops! Now we have all questions answered.
