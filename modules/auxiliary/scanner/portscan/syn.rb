# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'TCP SYN Port Scanner',
      'Description' => %q(
        Enumerate open TCP services using a raw SYN scan.
      ),
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
                       OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
                       OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
                       OptInt.new('BATCHSIZE', [true, "The number of hosts to scan per set", 256]),
                       OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
                       OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0]),
                       OptString.new('INTERFACE', [false, 'The name of the interface'])
                     ], self.class)

    deregister_options('FILTER', 'PCAPFILE')
  end

  # No IPv6 support yet
  def support_ipv6?
    false
  end

  def run_batch_size
    datastore['BATCHSIZE'] || 256
  end

  def run_batch(hosts)
    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    raise Msf::OptionValidateError, ['PORTS'] if ports.empty?

    jitter_value = datastore['JITTER'].to_i
    raise Msf::OptionValidateError, ['JITTER'] if jitter_value < 0

    delay_value = datastore['DELAY'].to_i
    raise Msf::OptionValidateError, ['DELAY'] if delay_value < 0

    open_pcap
    pcap = capture

    to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

    # we copy the hosts because some may not be reachable and need to be ejected
    host_queue = hosts.dup
    # Spread the load across the hosts
    ports.each do |dport|
      host_queue.each do |dhost|
        shost, sport = getsource(dhost)

        capture.setfilter(getfilter(shost, sport, dhost, dport))

        # Add the delay based on JITTER and DELAY if needs be
        add_delay_jitter(delay_value, jitter_value)

        begin
          probe = buildprobe(shost, sport, dhost, dport)

          unless capture_sendto(probe, dhost)
            host_queue.delete(dhost)
            next
          end

          reply = probereply(capture, to)

          next unless reply

          if reply.is_tcp? && (reply.tcp_flags.syn == 1) && (reply.tcp_flags.ack == 1)
            print_status(" TCP OPEN #{dhost}:#{dport}")
            report_service(host: dhost, port: dport)
          end
        rescue ::Exception
          print_error("Error: #{$ERROR_INFO.class} #{$ERROR_INFO}")
        end
      end
    end

    close_pcap
  end

  def getfilter(shost, sport, dhost, dport)
    # Look for associated SYN/ACKs and RSTs
    "tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " \
      "src host #{dhost} and src port #{dport} and " \
      "dst host #{shost} and dst port #{sport}"
  end

  def getsource(dhost)
    # srcip, srcport
    [ Rex::Socket.source_address(dhost), rand(0xffff - 1025) + 1025 ]
  end

  def buildprobe(shost, sport, dhost, dport)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = shost
    p.ip_daddr = dhost
    p.tcp_sport = sport
    p.tcp_flags.ack = 0
    p.tcp_flags.syn = 1
    p.tcp_dport = dport
    p.tcp_win = 3072
    p.recalc
    p
  end

  def probereply(pcap, to)
    reply = nil
    begin
      Timeout.timeout(to) do
        pcap.each do |r|
          pkt = PacketFu::Packet.parse(r)
          next unless pkt.is_tcp?
          reply = pkt
          break
        end
      end
    rescue Timeout::Error
    end
    reply
  end
end
