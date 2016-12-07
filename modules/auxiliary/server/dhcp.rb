# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/dhcp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DHCPServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'DHCP Server',
      'Description' => %q(
        This module provides a DHCP service
      ),
      'Author'      => [ 'scriptjunkie', 'apconole@yahoo.com' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )
  end

  def run
    @dhcp = Rex::Proto::DHCP::Server.new(datastore)

    print_status("Starting DHCP server...")
    @dhcp.start
    add_socket(@dhcp.sock)

    # Wait for finish..
    select(nil, nil, nil, 2) while @dhcp.thread.alive?

    print_status("Stopping DHCP server...")
    @dhcp.stop
  end
end
