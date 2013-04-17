require 'rake'

desc "Default: \"rake help\""
task :default => :help

desc "Display the help screen."
task( :help ) {
	puts "rake [options]"
	puts "    -T, --tasks [prefix]            List the tasks."
	puts "    -h, -H, --help                  Display the Rake help."
	puts "Tasks:"
	system "rake -T"
}

desc "Build the Gem."
task( :gem ) {
	sh "gem build *.gemspec"
}

desc "Remove generated files."
task( :clean ) {
	sh "[ ! -e *-*.gem ] || rm *-*.gem"
}

desc "Run tests."
task( :test => [] ) {
	$:.unshift( ::File.expand_path( 'lib', ::File.dirname( __FILE__ )))
	if ::ENV['TESTCASE']
		test_files_ = ::Dir.glob( "test/#{::ENV['TESTCASE']}.rb" )
	else
		test_files_ = ::Dir.glob( "test/**/*_{test,spec}.rb" )
	end
	test_files_.each { |path_|
		load path_
		puts "Loaded testcase #{path_}"
	}
}


# Local Variables:
# mode: ruby
# indent-tabs-mode: t
# End:

