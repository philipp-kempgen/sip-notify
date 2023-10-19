# -*- coding: utf-8 -*-

# Send SIP "NOTIFY" "check-sync" events.

require 'socket'
require 'securerandom'
require 'rbconfig'
require 'bindata'


class SipNotifyError < RuntimeError; end

class SipNotify
	
	REQUEST_METHOD = 'NOTIFY'.freeze
	VIA_BRANCH_TOKEN_MAGIC = 'z9hG4bK'.freeze  # http://tools.ietf.org/html/rfc3261#section-8.1.1.7
	
	# Whether the length in a raw IP packet must be little-endian
	# (i.e. native-endian) and the Kernel auto-reverses the value.
	# IP spec. says big-endian (i.e. network order).
	RAW_IP_PKT_LITTLE_ENDIAN_LENGTH    = !! ::RbConfig::CONFIG['host_os'].to_s.match( /\A darwin/xi )
	
	# Whether the fragment offset in a raw IP packet must be
	# little-endian (i.e. native-endian) and the Kernel
	# auto-reverses the value. IP spec. says big-endian (i.e.
	# network order).
	RAW_IP_PKT_LITTLE_ENDIAN_FRAG_OFF  = !! ::RbConfig::CONFIG['host_os'].to_s.match( /\A darwin/xi )
	
	SOCK_OPT_LEVEL_IP = (
		if defined?( ::Socket::SOL_IP )
			::Socket::SOL_IP      # Linux
		else
			::Socket::IPPROTO_IP  # Solaris, BSD, Darwin
		end
	)
	
	# Pre-defined event types.
	#
	EVENT_TEMPLATES = {
		
		# Compatibility.
		# The most widely implemented event:
		:'compat-check-cfg'        => { :event => 'check-sync' },
		
		# Snom:
		:'snom-check-cfg'          => { :event => 'check-sync;reboot=false' },
		:'snom-reboot'             => { :event => 'reboot' },
		
		# Polycom:
		# In the Polycom's sip.cfg make sure that
		# voIpProt.SIP.specialEvent.checkSync.alwaysReboot="0"
		# (0 will only reboot if the files on the settings server have changed.)
		:'polycom-check-cfg'       => { :event => 'check-sync' },
		:'polycom-reboot'          => { :event => 'check-sync' },
		
		# Aastra:
		:'aastra-check-cfg'        => { :event => 'check-sync' },
		:'aastra-reboot'           => { :event => 'check-sync' },
		:'aastra-xml'              => { :event => 'aastra-xml' },  # triggers the XML SIP NOTIFY action URI
		
		# Sipura by Linksys by Cisco:
		:'sipura-check-cfg'        => { :event => 'resync' },
		:'sipura-reboot'           => { :event => 'reboot' },
		:'sipura-get-report'       => { :event => 'report' },
		
		# Linksys by Cisco:
		:'linksys-check-cfg'       => { :event => 'restart_now' },  # warm restart
		:'linksys-reboot'          => { :event => 'reboot_now' },  # cold reboot
		
		# Cisco:
		# In order for "cisco-check-cfg"/"cisco-reboot" to work make
		# sure the syncinfo.xml has a different sync number than the
		# phone's current sync number (e.g. by setting the "sync"
		# parameter to "0" and having "1" in syncinfo.xml). If that
		# is the case the phone will reboot (no check-sync without
		# reboot).
		#
		# http://dxr.mozilla.org/mozilla-central/media/webrtc/signaling/src/sipcc/core/sipstack/ccsip_task.c#l2358
		# http://dxr.mozilla.org/mozilla-central/media/webrtc/signaling/src/sipcc/core/sipstack/h/ccsip_protocol.h#l196
		# http://dxr.mozilla.org/mozilla-central/media/webrtc/signaling/src/sipcc/core/sipstack/h/ccsip_protocol.h#l224
		# http://dxr.mozilla.org/mozilla-central/media/webrtc/signaling/src/sipcc/core/sipstack/ccsip_pmh.c#l4978
		# https://issues.asterisk.org/jira/secure/attachment/32746/sip-trace-7941-9-1-1SR1.txt
		# telnet: "debug sip-task"
		
		:'cisco-check-cfg'         => { :event => 'check-sync' },
		:'cisco-reboot'            => { :event => 'check-sync' },
		
		# Phone must be in CCM (Cisco Call Manager) registration
		# mode (TCP) for "service-control" events to work, and the
		# firmware must be >= 8.0. 7905/7912/7949/7969.
		
		# Causes the phone to unregister, request config file
		# (SIP{mac}.cnf), register.
		:'cisco-sc-restart-unregistered' => { :event => 'service-control',
			:content_type => 'text/plain',
			:content => [
				'action=' + 'restart',
				'RegisterCallId=' + '{' + '' + '}',  # not registered
				'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
				'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
				'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
				'',
			].join("\r\n"),
		},
		
		#:'cisco-sc-restart'        => { :event => 'service-control',
		#	:content_type => 'text/plain',
		#	:content => [
		#		'action=' + 'restart',
		#	#	'RegisterCallId=' + '{' + '${SIPPEER(${PEERNAME},regcallid)}' '}',
		#		'RegisterCallId=' + '{0022555d-aa850002-a2b54180-bb702fe7@192.168.1.130}',
		#		#00119352-91f60002-1df7530e-4190441e@192.168.1.130
		#		#00119352-91f60041-4a7455b9-00e0f121@192.168.1.130
		#		'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'',
		#	].join("\r\n"),
		#},
		
		# Causes the phone to unregister and do a full reboot cycle.
		:'cisco-sc-reset-unregistered' => { :event => 'service-control',
			:content_type => 'text/plain',
			:content => [
				'action=' + 'reset',
				'RegisterCallId=' + '{' + '' + '}',  # not registered
				'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
				'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
				'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
				'',
			].join("\r\n"),
		},
		
		#:'cisco-sc-reset'          => { :event => 'service-control',
		#	:content_type => 'text/plain',
		#	:content => [
		#		'action=' + 'reset',
		#	#	'RegisterCallId=' + '{' + '${SIPPEER(${PEERNAME},regcallid)}' '}',
		#		'RegisterCallId=' + '{123}',
		#		'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'',
		#	].join("\r\n"),
		#},
		
		# Causes the phone to unregister, request dialplan
		# (dialplan.xml) and config file (SIP{mac}.cnf), register.
		# This is the action to send if the config "file" on the
		# TFTP server changes.
		:'cisco-sc-check-unregistered' => { :event => 'service-control',
			:content_type => 'text/plain',
			:content => [
				'action=' + 'check-version',
				'RegisterCallId=' + '{' + '' + '}',  # not registered
				'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
				'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
				'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
				'',
			].join("\r\n"),
		},
		
		#:'cisco-sc-apply-config' => { :event => 'service-control',
		#	:content_type => 'text/plain',
		#	:content => [
		#		'action=' + 'apply-config',
		#		'RegisterCallId=' + '{' + '' + '}',  # not registered
		#		'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'FeatureControlVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'CUCMResult=' + '{' + 'config_applied' + '}',  # "no_change" / "config_applied" / "reregister_needed"
		#		'FirmwareLoadId=' + '{' + 'SIP70.8-4-0-28S' + '}',
		#		'LoadServer=' + '{' + '192.168.1.97' + '}',
		#		'LogServer=' + '{' + '192.168.1.97' + '}',  # <ipv4 address or ipv6 address or fqdn> <port>  // This is used for ppid
		#		'PPID=' + '{' + 'disabled' + '}',  # "enabled" / "disabled"  // peer-to-peer upgrade
		#		'',
		#	].join("\r\n"),
		#},
		
		#:'cisco-sc-call-preservation' => { :event => 'service-control',
		#	:content_type => 'text/plain',
		#	:content => [
		#		'action=' + 'call-preservation',
		#		'RegisterCallId=' + '{' + '' + '}',  # not registered
		#		'ConfigVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'DialplanVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'SoftkeyVersionStamp=' + '{' + '0000000000000000' + '}',
		#		'',
		#	].join("\r\n"),
		#},
		
		# Grandstream:
		:'grandstream-check-cfg'   => { :event => 'sys-control' },
		:'grandstream-reboot'      => { :event => 'sys-control' },
		:'grandstream-idle-screen-refresh' => { :event => 'x-gs-screen' },
		
		# Gigaset (Pro Nxxx):
		:'gigaset-check-cfg'       => { :event => 'check-sync;reboot=false' },
		:'gigaset-reboot'          => { :event => 'check-sync;reboot=true' },
		
		# Siemens (Enterprise Networks) OpenStage:
		:'siemens-check-cfg'       => { :event => 'check-sync;reboot=false' },
		:'siemens-reboot'          => { :event => 'check-sync;reboot=true' },
		
		# Yealink:
		:'yealink-check-cfg'       => { :event => 'check-sync;reboot=true' },  #OPTIMIZE can do without reboot?
		:'yealink-reboot'          => { :event => 'check-sync;reboot=true' },
		
		# Thomson (ST2030?):
		:'thomson-check-cfg'       => { :event => 'check-sync;reboot=false' },
		:'thomson-reboot'          => { :event => 'check-sync;reboot=true' },
		:'thomson-talk'            => { :event => 'talk' },
		:'thomson-hold'            => { :event => 'hold' },
		
		# Misc:
		#
		
		:'mwi-clear-full'          => { :event => 'message-summary',
			:content_type => 'application/simple-message-summary',
			:content => [
				'Messages-Waiting: ' + 'no',  # "yes"/"no"
			#	'Message-Account: sip:voicemail@127.0.0.1',
				'voice-message'       + ': 0/0 (0/0)',
				'fax-message'         + ': 0/0 (0/0)',
				'pager-message'       + ': 0/0 (0/0)',
				'multimedia-message'  + ': 0/0 (0/0)',
				'text-message'        + ': 0/0 (0/0)',
				'none'                + ': 0/0 (0/0)',
				'',
			],#.join("\r\n"),
		},
		
		:'mwi-clear-simple'        => { :event => 'message-summary',
			:content_type => 'application/simple-message-summary',
			:content => [
				'Messages-Waiting: ' + 'no',  # "yes"/"no"
			#	'Message-Account: sip:voicemail@127.0.0.1',
				'voice-message'       + ': 0/0',
				'',
			],#.join("\r\n"),
		},
		
		:'mwi-test-full'           => { :event => 'message-summary',
			:content_type => 'application/simple-message-summary',
			:content => [
				'Messages-Waiting: ' + 'yes',  # "yes"/"no"
			#	'Message-Account: sip:voicemail@127.0.0.1',
				'voice-message'       + ': 3/4 (1/2)',
				'fax-message'         + ': 3/4 (1/2)',
				'pager-message'       + ': 3/4 (1/2)',
				'multimedia-message'  + ': 3/4 (1/2)',
				'text-message'        + ': 3/4 (1/2)',
				'none'                + ': 3/4 (1/2)',
				'',
			],#.join("\r\n"),
		},
		
		:'mwi-test-simple'         => { :event => 'message-summary',
			:content_type => 'application/simple-message-summary',
			:content => [
				'Messages-Waiting: ' + 'yes',  # "yes"/"no"
			#	'Message-Account: sip:voicemail@127.0.0.1',
				'voice-message'       + ': 3/4',
				'',
			],#.join("\r\n"),
		},
		
	}
	
	def initialize( host, opts=nil )
		re_initialize!( host, opts )
	end
	
	def re_initialize!( host, opts=nil )
		@opts = {
			:host => host,
			:domain => host,
			:port => 5060,
			:user => nil,
			:to_user => nil,
			:verbosity => 0,
			:via_rport => true,
			:event => nil,
			:content_type => nil,
			:content => nil,
		}.merge( opts || {} )
		self
	end
	
	def self.event_templates
		EVENT_TEMPLATES
	end
	
	# DSCP value (Differentiated Services Code Point).
	#
	def ip_dscp
		@ip_dscp ||= 0b110_000  # == 48 == 0x30 == DSCP CS6 ~= IP Precedence 5
	end
	
	# IP ToS value (Type of Service).
	#
	def ip_tos
		@ip_tos ||= (ip_dscp << 2)
	end
	
	# Create a socket.
	#
	def socket
		if @socket
			if @socket_is_raw
				if (! @opts[:spoof_src_addr]) || @opts[:spoof_src_addr].empty?
					@socket = nil
				end
			else
				if @opts[:spoof_src_addr]
					@socket = nil
				end
			end
		end
		
		if @opts[:spoof_src_addr]
			unless @raw_socket
				#local_addr, local_port = * our_addr
				#if @opts[:spoof_src_addr] != local_addr
					puts "Spoofing source IP address: #{@opts[:spoof_src_addr].inspect}."  if @opts[:verbosity] >= 1
					@raw_socket = raw_socket
				#end
			end
			@socket = @raw_socket
			@socket_is_raw = true
			return @raw_socket
		end
		
		unless @socket
			begin
				::BasicSocket.do_not_reverse_lookup = true
				
				@socket = ::Socket.new( ::Socket::AF_INET, ::Socket::SOCK_DGRAM )
				@socket.setsockopt( ::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1 )
				@socket.setsockopt( SOCK_OPT_LEVEL_IP, ::Socket::IP_TOS, ip_tos )
				@socket.setsockopt( SOCK_OPT_LEVEL_IP, ::Socket::IP_TTL, 255 )  # default 64
				#@socket.settimeout( 1.0 )
			
			rescue ::SystemCallError, ::SocketError, ::IOError => e
				socket_destroy!
				raise ::SipNotifyError.new( "Failed to create socket: #{e.message} (#{e.class.name})" )
			end
			
			begin
				sock_addr = ::Socket.sockaddr_in( @opts[:port], @opts[:host] )
				@socket.connect( sock_addr )
			
			rescue ::SystemCallError, ::SocketError, ::IOError => e
				socket_destroy!
				raise ::SipNotifyError.new( "Failed to connect socket to %{addr}: #{e.message} (#{e.class.name})" % {
					:addr => ip_addr_and_port_url_repr( @opts[:host], @opts[:port] ),
				})
			end
		end
		
		@socket_is_raw = false
		return @socket
	end
	private :socket
	
	# Close and unset the socket.
	#
	def socket_destroy!
		@socket.close()  if @socket && ! @socket.closed?
		@socket = nil
	end
	
	# Create a raw socket.
	#
	def raw_socket
		begin
			::BasicSocket.do_not_reverse_lookup = true
			
			#sock = ::Socket.new( ::Socket::PF_INET, ::Socket::SOCK_RAW, ::Socket::IPPROTO_RAW )
			sock = ::Socket.new( ::Socket::PF_INET, ::Socket::SOCK_RAW, ::Socket::IPPROTO_UDP )
			
			# Make sure IP_HDRINCL is set on the raw socket,
			# otherwise the kernel would prepend outbound packets
			# with an IP header.
			# https://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man4/ip.4.html
			#
			so = sock.getsockopt( SOCK_OPT_LEVEL_IP, ::Socket::IP_HDRINCL )
			if so.bool == false || so.int == 0 || so.data == [0].pack('L')
				#puts "IP_HDRINCL is supposed to be the default for IPPROTO_RAW."
				# ... not on Darwin though.
				sock.setsockopt( SOCK_OPT_LEVEL_IP, ::Socket::IP_HDRINCL, true )
			end
			
			sock.setsockopt( ::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1 )
		
		rescue ::Errno::EPERM => e
			$stderr.puts "Must be run as root."
			raise ::SipNotifyError.new( "Failed to create socket: #{e.message} (#{e.class.name})" )
		rescue ::SystemCallError, ::SocketError, ::IOError => e
			raise ::SipNotifyError.new( "Failed to create socket: #{e.message} (#{e.class.name})" )
		end
		
		return sock
	end
	
	# The socket type.
	#
	# `nil` if no socket.
	# 1 = Socket::SOCK_STREAM
	# 2 = Socket::SOCK_DGRAM
	# 3 = Socket::SOCK_RAW
	# 4 = Socket::SOCK_RDM
	# 5 = Socket::SOCK_SEQPACKET
	#
	def socket_type
		@socket ? @socket.local_address.socktype : nil
	end
	
	# The UDP source port number to use for spoofed packets.
	#
	def spoof_src_port
		# Note:
		# Port 5060 is likely to cause the actual PBX/proxy receive
		# responses for out NOTIFY requests.
		# Port 0 is a valid port to use for UDP if responses are to
		# be irgnored, but is likely to be taken for an invalid port
		# number in devices.
		65535
	end
	private :spoof_src_port
	
	# Return out address.
	#
	def our_addr
		if @opts[:spoof_src_addr]
			@our_addr = [ @opts[:spoof_src_addr], spoof_src_port ]
		end
		
		unless @our_addr
			our_sock_addr = socket.getsockname()
			local_port, local_addr = * ::Socket.unpack_sockaddr_in( our_sock_addr )
			@our_addr = [ local_addr, local_port ]
		end
		
		@our_addr
	end
	private :our_addr
	
	# Returns an IP address (or hostname) in URL representation.
	# I.e. an IPv6 address will be enclosed in "["..."]".
	#
	def self.ip_addr_url_repr( host )
		host.include?(':') ? "[#{host}]" : host.to_s
	end
	
	# Shortcut as an instance method
	#
	def ip_addr_url_repr( host )
		self.class.ip_addr_url_repr( host )
	end
	
	# Returns an IP address (or hostname) and port number in URL
	# representation.
	# I.e. an IPv6 address will be enclosed in "["..."]".
	#
	def self.ip_addr_and_port_url_repr( host, port )
		"%{addr}:%{port}" % { :addr => ip_addr_url_repr( host ), :port => port }
	end
	
	# Shortcut as an instance method
	#
	def ip_addr_and_port_url_repr( host, port )
		self.class.ip_addr_and_port_url_repr( host, port )
	end
	
	# Send the SIP NOTIFY message.
	#
	def send
		begin
			sip_msg = to_s
			if @opts[:verbosity] >= 3
				puts "-----------------------------------------------------------------{"
				puts sip_msg.gsub( /\r\n/, "\n" )
				puts "-----------------------------------------------------------------}"
			end
			
			socket  # Touch socket
			
			case socket_type
				
				when ::Socket::SOCK_DGRAM
					num_bytes_written = nil
					2.times {
						num_bytes_written = socket.write( sip_msg )
					}
				
				when ::Socket::SOCK_RAW
					#local_addr, local_port = * our_addr
					
					::BasicSocket.do_not_reverse_lookup = true
					
					src_addr = @opts[:spoof_src_addr]
					src_addr_info = (::Addrinfo.getaddrinfo( src_addr, 'sip', nil, :DGRAM, ::Socket::IPPROTO_UDP, ::Socket::AI_V4MAPPED || ::Socket::AI_ALL ) || []).select{ |a|
						a.afamily == ::Socket::AF_INET
					}.first
					src_sock_addr = src_addr_info.to_sockaddr
					
					src_addr_ipv4_packed  = src_sock_addr[4,4]
					src_port_packed       = src_sock_addr[2,2]
					
					dst_addr = @opts[:host]
					dst_addr_info = (::Addrinfo.getaddrinfo( dst_addr, 'sip', nil, :DGRAM, ::Socket::IPPROTO_UDP, ::Socket::AI_V4MAPPED || ::Socket::AI_ALL ) || []).select{ |a|
						a.afamily == ::Socket::AF_INET
					}.first
					dst_sock_addr = dst_addr_info.to_sockaddr
					
					dst_addr_ipv4_packed  = dst_sock_addr[4,4]
					dst_port_packed       = dst_sock_addr[2,2]
					
					#udp_pkt = UdpPktBitStruct.new { |b|
					#	b.src_port = spoof_src_port
					#	b.dst_port = 5060
					#	b.body = sip_msg.to_s
					#	b.udp_len  = b.length
					#	b.udp_sum  = 0
					#}
					
					udp_pkt = UdpPktBinData.new
					udp_pkt.src_port  = spoof_src_port
					udp_pkt.dst_port  = 5060
					udp_pkt.data      = sip_msg.to_s
					udp_pkt.len       = 4 + udp_pkt.data.bytesize
					udp_pkt.checksum  = 0  # none. UDP checksum is optional.
					
					#ip_pkt = IpPktBitStruct.new { |b|
					#	# ip_v and ip_hl are set for us by IpPktBitStruct class
					#	b.ip_tos  = ip_tos
					#	b.ip_id   = 0
					#	b.ip_off  = 0
					#	b.ip_ttl  = 255  # default: 64
					#	b.ip_p    = ::Socket::IPPROTO_UDP
					#	b.ip_src  = @opts[:spoof_src_addr]
					#	b.ip_dst  = @opts[:host]
					#	b.body    = udp_pkt.to_s
					#	b.ip_len  = b.length
					#	b.ip_sum  = 0  # Linux/Darwin will calculate this for us (QNX won't)
					#}
					
					ip_pkt = IpPktBinData.new
					ip_pkt.hdr_len   = 5  # 5 * 8 bytes == 20 bytes
					ip_pkt.tos       = ip_tos
					ip_pkt.ident     = 0  # kernel sets appropriate value
					ip_pkt.flags     = 0
					frag_off = 0
					if RAW_IP_PKT_LITTLE_ENDIAN_FRAG_OFF && frag_off != 0
						ip_pkt.frag_os   = [ frag_off ].pack('n').unpack('S').first
					else
						ip_pkt.frag_os   =   frag_off
					end
					ip_pkt.ttl       = 255  # default: 64
					ip_pkt.proto     = ::Socket::IPPROTO_UDP
					ip_pkt.src_addr  = src_addr_ipv4_packed .unpack('N').first
					ip_pkt.dst_addr  = dst_addr_ipv4_packed .unpack('N').first
					ip_pkt.data      = udp_pkt.to_binary_s
					#len = (ip_pkt.hdr_len * 8) + ip_pkt.data.bytesize
					len = ip_pkt.to_binary_s.bytesize
					if RAW_IP_PKT_LITTLE_ENDIAN_LENGTH
						ip_pkt.len       = [ len ].pack('n').unpack('S').first
					else
						ip_pkt.len       =   len
					end
					ip_pkt.checksum  = 0  # Linux/Darwin will calculate this for us (QNX won't)
					
					#puts "-" * 80,
					#	"UDP packet:",
					#	udp_pkt.inspect,
					#	"-" * 80,
					#	udp_pkt.to_binary_s.inspect,
					#	"-" * 80
					
					#puts "-" * 80,
					#	"IP packet:",
					#	ip_pkt.inspect,
					#	"-" * 80,
					#	ip_pkt.to_binary_s.inspect,
					#	"-" * 80
					
					sock_addr = ::Socket.sockaddr_in( @opts[:port], @opts[:host] )
					
					# Send 2 times. (UDP is an unreliable transport.)
					num_bytes_written = nil
					2.times {
						num_bytes_written = socket.send( ip_pkt.to_binary_s, 0, sock_addr )
					}
				
				else
					raise ::SipNotifyError.new( "Socket type not supported." )
			end
			
			puts "Sent NOTIFY to #{@opts[:host]}."  if @opts[:verbosity] >= 1
			return num_bytes_written
		
		rescue ::SystemCallError, ::SocketError, ::IOError => e
			socket_destroy!
			return false
		end
	end
	
	# Generate a random token.
	#
	def self.random_token( num_bytes=5 )
		::SecureRandom.random_bytes( num_bytes ).unpack('H*').first
	end
	
	# Shortcut as an instance method.
	#
	def random_token
		self.class.random_token
	end
	private :random_token
	
	# Build the SIP message.
	#
	def to_s
		local_addr, local_port = * our_addr
		local_ip_addr_and_port_url_repr = ip_addr_and_port_url_repr( local_addr, local_port )
		puts "Local address is: #{local_ip_addr_and_port_url_repr}"  if @opts[:verbosity] >= 2
		
		now = ::Time.now()
		
		transport = 'UDP'  # "UDP"/"TCP"/"TLS"/"SCTP"
		
		ra =   60466176  # 100000 (36)
		rb = 2000000000  # x2qxvk (36)
		
		via_branch_token = VIA_BRANCH_TOKEN_MAGIC + '_' + random_token()
		
		ruri_scheme = 'sip'  # "sip"/"sips"
		if @opts[:user] == nil
			ruri_userinfo = ''
		elsif @opts[:user] == ''
			ruri_userinfo = "#{@opts[:user]}@"
			# This isn't a valid SIP Request-URI as the user must not be
			# empty if the userinfo is present ("@").
		else
			ruri_userinfo = "#{@opts[:user]}@"
		end
		
		ruri_hostport = ip_addr_and_port_url_repr( @opts[:host], @opts[:port] )
		ruri = "#{ruri_scheme}:#{ruri_userinfo}#{ruri_hostport}"
		
		from_display_name = 'Provisioning'
		from_scheme = 'sip'
		from_user = '_'
		from_userinfo = "#{from_user}@"
		#from_hostport = domain  # should be a domain
		from_hostport = ip_addr_url_repr( local_addr )
		from_uri = "#{from_scheme}:#{from_userinfo}#{from_hostport}"
		from_tag_param_token = random_token()
		
		to_scheme = 'sip'
		#to_hostport = domain
		to_hostport = ip_addr_url_repr( @opts[:host] )
		if @opts[:to_user] != nil
			to_userinfo = "#{@opts[:to_user]}@"
			# Even for to_user == '' (which is invalid).
		else
			if @opts[:user] == nil
				to_userinfo = ''
			elsif @opts[:user] == ''
				to_userinfo = '@'
				# This isn't a valid SIP To-URI as the user must not be
				# empty if the userinfo is present ("@").
			else
				to_userinfo = "#{@opts[:user]}@"
			end
		end
		to_uri = "#{to_scheme}:#{to_userinfo}#{to_hostport}"
		
		contact_display_name = from_display_name
		contact_scheme = 'sip'
		contact_user = '_'
		contact_userinfo = "#{contact_user}@"
		contact_hostport = local_ip_addr_and_port_url_repr
		contact_uri = "#{contact_scheme}:#{contact_userinfo}#{contact_hostport}"		
		
		call_id = "#{random_token()}@#{local_ip_addr_and_port_url_repr}"
		
		cseq_num = 102
		cseq = "#{cseq_num} #{REQUEST_METHOD}"
		
		max_forwards = 70
		
		unless @opts[:event]
			event_package = 'check-sync'
			event_type = event_package + ''
			@opts[:event] = "#{event_type};reboot=false"
		end
		
		if @opts[:content]
			if @opts[:content].kind_of?( ::Array )
				body = @opts[:content].map(& :to_s).join("\r\n")
			else
				body = @opts[:content].to_s
			end
		else
			body = ''
		end
		body.encode!( ::Encoding::UTF_8, :undef => :replace, :invalid => :replace )
		
		sip_msg = [
			'%{request_method} %{ruri} SIP/2.0',
			'Via: SIP/2.0/%{transport} %{via_hostport}' +
				';branch=%{via_branch_token}' +
				'%{rport_param}',
			'From: %{from_display_name} <%{from_uri}>' +
				';tag=%{from_tag_param_token}',
			'To: <%{to_uri}>',
			'Contact: %{contact_display_name} <%{contact_uri}>',
			'Call-ID: %{call_id}',
			'CSeq: %{cseq}',
			'Date: %{date}',
			'Max-Forwards: %{max_forwards}',
		#	'Allow: %{allow}',
			'Subscription-State: %{subscription_state}',
			'Event: %{event}',
			(@opts[:content_type] ?
				'Content-Type: %{content_type}' :
				nil),
			'Content-Length: %{content_length}',
			'',
			body,
		].compact.join("\r\n") % {
			:request_method => REQUEST_METHOD,
			:ruri => ruri,
			:transport => transport,
			:via_hostport => local_ip_addr_and_port_url_repr,
			:via_branch_token => via_branch_token,
			:rport_param => (@opts[:via_rport] ? ';rport' : ''),
			:from_display_name => from_display_name,
			:from_uri => from_uri,
			:from_tag_param_token => from_tag_param_token,
			:to_uri => to_uri,
			:contact_display_name => contact_display_name,
			:contact_uri => contact_uri,
			:call_id => call_id,
			:cseq => cseq,
			:date => now.utc.strftime('%c') +' GMT',  # must be "GMT"
			:max_forwards => max_forwards,
		#	:allow => [ 'ACK' ].join(', '),
			:subscription_state => 'active',
			:event => @opts[:event].to_s,
			:content_type => @opts[:content_type].to_s.gsub(/\s+/, ' '),
			:content_length => body.bytesize.to_s,
		}
		sip_msg.encode!( ::Encoding::UTF_8, :undef => :replace, :invalid => :replace )
		sip_msg
	end
	
	# Send variations of the SIP message.
	#
	def self.send_variations( host, opts=nil )
		opts ||= {}
		opts[:domain] ||= host
		
		# Create a single SipNotify instance so it will reuse the
		# socket.
		notify = ::SipNotify.new( nil )
		
		if opts[:user] && ! opts[:user].empty?
			# Send NOTIFY with user:
			puts "Sending NOTIFY with user ..."  if opts[:verbosity] >= 1
			notify.re_initialize!( host, opts.merge({
			})).send
		end
		
		#if true
			# Send NOTIFY without user:
			puts "Sending NOTIFY without user ..."  if opts[:verbosity] >= 1
			notify.re_initialize!( host, opts.merge({
				:user => nil,
			})).send
		#end
		
		#if true
			# Send invalid NOTIFY with empty user ("") in Request-URI:
			puts "Sending invalid NOTIFY with empty user ..."  if opts[:verbosity] >= 1
			notify.re_initialize!( host, opts.merge({
				:user => '',
			})).send
		#end
		
		#if true
			# Send invalid NOTIFY with empty user ("") in Request-URI
			# but non-empty user in To-URI:
			# (for Cisco 7960/7940)
			puts "Sending invalid NOTIFY with empty user in Request-URI but non-empty user in To-URI ..."  if opts[:verbosity] >= 1
			notify.re_initialize!( host, opts.merge({
				:user => '',
				:to_user => '_',
			})).send
		#end
		
		notify.socket_destroy!
		
		nil
	end
	
end


# An IP paket.
#
class IpPktBinData < BinData::Record
	endian :big
	bit4      :vers, :value => 4     # IP version
	bit4      :hdr_len               # header length
	uint8     :tos                   # TOS / DiffServ
	uint16    :len                   # total length
	uint16    :ident                 # identifier
	bit3      :flags                 # flags
	bit13     :frag_os               # fragment offset
	uint8     :ttl                   # time-to-live
	uint8     :proto                 # IP protocol
	uint16    :checksum              # checksum
	uint32    :src_addr              # source IP address
	uint32    :dst_addr              # destination IP address
	string    :options, :read_length => :options_length_in_bytes
	string    :data, :read_length => lambda { total_length - header_length_in_bytes }
	
	def header_length_in_bytes
		hdr_len * 4
	end

	def options_length_in_bytes
		header_length_in_bytes - 20
	end
end


# An UDP packet (payload in an IP packet).
#
class UdpPktBinData < BinData::Record
	endian :big
	uint16    :src_port
	uint16    :dst_port
	uint16    :len
	uint16    :checksum
	string    :data, :read_length => :len
end


# vim:noexpandtab:

