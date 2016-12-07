# frozen_string_literal: true
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to imporve this script, please try to port it as a post
# module instead. Thank you.
##

# Meterpreter script that display local subnets
# Provided by Nicob <nicob [at] nicob.net>
# Ripped from http://blog.metasploit.com/2006/10/meterpreter-scripts-and-msrt.html

@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ]
)
def usage
  print_line("Get a list of local subnets based on the host's routes")
  print_line("USAGE: run get_local_subnets")
  print_line(@@exec_opts.usage)
  raise Rex::Script::Completed
end

@@exec_opts.parse(args) do |opt, _idx, _val|
  case opt
  when "-h"
    usage
  end
end

client.net.config.each_route do |route|
  # Remove multicast and loopback interfaces
  next if route.subnet =~ /^(224\.|127\.)/
  next if route.subnet == '0.0.0.0'
  next if route.netmask == '255.255.255.255'
  print_line("Local subnet: #{route.subnet}/#{route.netmask}")
end
