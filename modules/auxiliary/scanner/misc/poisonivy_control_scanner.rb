# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Poison Ivy Command and Control Scanner',
      'Description' => %q{
        Enumerate Poison Ivy Command and Control (C&C) on ports 3460, 80, 8080 and 443. Adaptation of iTrust Python script.
      },
      'Author'      => ['SeawolfRN'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PORTS', [true, "Ports to Check", "80,8080,443,3460"]),
        OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
        OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10])
      ], self.class
    )

    deregister_options('RPORT')
  end

  def run_host(ip)
    timeout = datastore['TIMEOUT'].to_i

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    raise Msf::OptionValidateError, ['PORTS'] if ports.empty?

    until ports.empty?
      t = []
      r = []
      begin
        1.upto(datastore['CONCURRENCY']) do
          this_port = ports.shift
          break unless this_port
          t << framework.threads.spawn("Module(#{refname})-#{ip}:#{this_port}", false, this_port) do |port|
            begin
              s = connect(false,
                          'RPORT' => port,
                          'RHOST' => ip,
                          'ConnectTimeout' => (timeout / 1000.0))
              r << [ip, port, "open", 'Unknown']
              s.puts("\x00" * 0x100, 0) # Send 0x100 zeros, wait for answer
              data = s.get_once(0x100) || ''
              if data.length == 0x100
                data = s.get_once(0x4) || ''
                if data == "\xD0\x15\x00\x00" # Signature for PIVY C&C
                  print_status("#{ip}:#{port} - C&C Server Found")
                  r << [ip, port, "open", 'Poison Ivy C&C']
                end
              end
            rescue ::Rex::ConnectionRefused
              vprint_status("#{ip}:#{port} - TCP closed")
              r << [ip, port, "closed", '']
            rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
            rescue ::Rex::Post::Meterpreter::RequestError
              raise $ERROR_INFO
            ensure
              begin
                disconnect(s)
              rescue
                nil
              end
            end
          end
        end
        t.each(&:join)

      rescue ::Timeout::Error
      ensure
        t.each do |x|
          begin
                      x.kill
                    rescue
                      nil
                    end
        end
      end

      r.each do |res|
        report_service(host: res[0], port: res[1], state: res[2], name: res[3])
      end
    end
  end
end
