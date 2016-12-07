# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'PcAnywhere UDP Service Discovery',
      'Description' => 'Discover active pcAnywhere services through UDP',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'http://www.unixwiz.net/tools/pcascan.txt']
        ]
    )

    register_options(
      [
        Opt::RPORT(5632)
      ], self.class
    )
  end

  def scanner_prescan(batch)
    print_status("Sending pcAnywhere discovery requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    scanner_send("NQ", ip, datastore['RPORT'])
    scanner_send("ST", ip, datastore['RPORT'])
  end

  def scanner_postscan(_batch)
    @results.keys.each do |ip|
      data = @results[ip]
      info = ""

      info << "Name: #{data[:name]} " if data[:name]

      info << "- #{data[:stat]} " if data[:stat]

      info << "( #{data[:caps]} ) " if data[:caps]

      report_service(host: ip, port: datastore['RPORT'], proto: 'udp', name: "pcanywhere_stat", info: info)
      report_note(host: ip, port: datastore['RPORT'], proto: 'udp', name: "pcanywhere_stat", update: :unique, ntype: "pcanywhere.status", data: data)
      print_status("#{ip}:#{datastore['RPORT']} #{info}")
    end
  end

  def scanner_process(data, shost, _sport)
    case data
    when /^NR(........................)(........)/

      name = Regexp.last_match(1).dup
      caps = Regexp.last_match(2).dup

      name = name.gsub(/_+$/, '').delete("\x00").strip
      caps = caps.gsub(/_+$/, '').delete("\x00").strip

      @results[shost] ||= {}
      @results[shost][:name] = name
      @results[shost][:caps] = caps

    when /^ST(.+)/
      @results[shost] ||= {}
      buff = Regexp.last_match(1).dup
      stat = 'Unknown'

      stat = "Available" if buff[2, 1].unpack("C")[0] == 67

      stat = "Busy" if buff[2, 1].unpack("C")[0] == 11

      @results[shost][:stat] = stat
    else
      print_error("#{shost} Unknown: #{data.inspect}")
    end
  end
end
