# -*- encoding: utf-8 -*-

lib_dir = File.expand_path( '../lib/', __FILE__ )
$LOAD_PATH.unshift( lib_dir )

#require 'sip_notify/version'

spec = Gem::Specification.new { |s|
	s.name         = 'sip-notify'
	s.version      = '0.0.1'
	s.summary      = "Sends SIP NOTIFY events."
	s.description  = "Sends SIP NOTIFY events (\"check-sync\" etc.)."
	s.author       = "Philipp Kempgen"
	s.homepage     = 'https://github.com/philipp-kempgen/sip-notify'
	s.platform     = Gem::Platform::RUBY
	s.require_path = 'lib'
	s.bindir       = 'bin'
	s.executables  = [ 'sip-notify' ]
	s.files        = Dir.glob( '{lib,bin}/**/*' ) + %w(
		README.md
	)
	
	s.add_dependency "bindata", "~> 1.4.5"
	#s.add_dependency "bit-struct", "~> 0.13.6"
}


# Local Variables:
# mode: ruby
# indent-tabs-mode: t
# End:

