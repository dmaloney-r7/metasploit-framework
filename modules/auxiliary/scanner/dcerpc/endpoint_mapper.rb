# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Endpoint Mapper Service Discovery',
      'Description' => %q(
        This module can be used to obtain information from the
        Endpoint Mapper service.
      ),
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOST')

    register_options(
      [
        Opt::RPORT(135)
      ], self.class
    )
  end

  # Obtain information about a single host
  def run_host(ip)
    begin

      ids = dcerpc_endpoint_list
      return unless ids
      name = nil
      ids.each do |id|
        next unless id[:prot]
        line = "#{id[:uuid]} v#{id[:vers]} "
        line << "#{id[:prot].upcase} "
        line << "(#{id[:port]}) " if id[:port]
        line << "(#{id[:pipe]}) " if id[:pipe]
        line << "#{id[:host]} " if id[:host]
        line << "[#{id[:note]}]" if id[:note]
        print_status(line)
        name = id[:host][2..-1] if id[:host] && (id[:host][0, 2] == "\\\\")
        next unless id[:prot].casecmp("tcp").zero? || id[:prot].casecmp("udp").zero?
        report_service(
          host: ip,
          port: id[:port],
          proto: id[:prot].downcase,
          name: "dcerpc",
          info: "#{id[:uuid]} v#{id[:vers]} #{id[:note]}"
        )
      end
      report_host(host: ip, name: name) if name
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: "dcerpc",
        info: "Endpoint Mapper (#{ids.length} services)"
      )

    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Rex::Proto::DCERPC::Exceptions::Fault
    rescue ::Exception => e
      print_error("#{ip}:#{rport} error: #{e}")
    end
  end
end
