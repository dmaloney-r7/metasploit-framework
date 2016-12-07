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
      'Name'        => 'UPnP SSDP M-SEARCH Information Discovery',
      'Description' => 'Discover information from UPnP-enabled systems',
      'Author'      => [ 'todb', 'hdm'], # Original scanner module and vuln info reporter, respectively
      'License'     => MSF_LICENSE
    )

    register_options([
                       Opt::RPORT(1900),
                       OptBool.new('REPORT_LOCATION', [true, 'This determines whether to report the UPnP endpoint service advertised by SSDP', false ])
                     ], self.class)
  end

  def rport
    datastore['RPORT']
  end

  def setup
    super
    @msearch_probe =
      "M-SEARCH * HTTP/1.1\r\n" \
      "Host:239.255.255.250:1900\r\n" \
      "ST:upnp:rootdevice\r\n" \
      "Man:\"ssdp:discover\"\r\n" \
      "MX:3\r\n" \
      "\r\n"
  end

  def scanner_prescan(batch)
    print_status("Sending UPnP SSDP probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    vprint_status "#{ip}:#{rport} - SSDP - sending M-SEARCH probe"
    scanner_send(@msearch_probe, ip, datastore['RPORT'])
  end

  def scanner_postscan(_batch)
    print_status "No SSDP endpoints found." if @results.empty?

    @results.each_pair do |skey, res|
      sinfo = res[:service]
      next unless sinfo

      bits = []

      [ :server, :location, :usn ].each do |k|
        bits << res[:info][k] if res[:info][k]
      end

      desc = bits.join(" | ")
      sinfo[:info] = desc

      res[:vulns] = []

      if res[:info][:server].to_s =~ /MiniUPnPd\/1\.0([\.\,\-\~\s]|$)/mi
        res[:vulns] << {
          name: "MiniUPnPd ProcessSSDPRequest() Out of Bounds Memory Access Denial of Service",
          refs: [ 'CVE-2013-0229' ]
        }
      end

      if res[:info][:server].to_s =~ /MiniUPnPd\/1\.[0-3]([\.\,\-\~\s]|$)/mi
        res[:vulns] << {
          name: "MiniUPnPd ExecuteSoapAction memcpy() Remote Code Execution",
          refs: [ 'CVE-2013-0230' ],
          port: res[:info][:ssdp_port] || 80,
          proto: 'tcp'
        }
      end

      if res[:info][:server].to_s =~ /Intel SDK for UPnP devices.*|Portable SDK for UPnP devices(\/?\s*$|\/1\.([0-5]\..*|8\.0.*|(6\.[0-9]|6\.1[0-7])([\.\,\-\~\s]|$)))/mi
        res[:vulns] << {
          name: "Portable SDK for UPnP Devices unique_service_name() Remote Code Execution",
          refs: [ 'CVE-2012-5958', 'CVE-2012-5959' ]
        }
      end

      if !res[:vulns].empty?
        vrefs = []
        res[:vulns].each do |v|
          v[:refs].each do |r|
            vrefs << r
          end
        end

        print_good("#{skey} SSDP #{desc} | vulns:#{res[:vulns].count} (#{vrefs.join(', ')})")
      else
        print_status("#{skey} SSDP #{desc}")
      end

      report_service(sinfo)

      res[:vulns].each do |v|
        report_vuln(
          host: sinfo[:host],
          port: v[:port] || sinfo[:port],
          proto: v[:proto] || 'udp',
          name: v[:name],
          info: res[:info][:server],
          refs: v[:refs]
        )
      end

      next unless res[:info][:ssdp_host]
      report_service(
        host: res[:info][:ssdp_host],
        port: res[:info][:ssdp_port],
        proto: 'tcp',
        name: 'upnp',
        info: res[:info][:location].to_s
      ) if datastore['REPORT_LOCATION']
    end
  end

  def scanner_process(data, shost, _sport)
    skey = "#{shost}:#{datastore['RPORT']}"

    @results[skey] ||= {
      info: {},
      service: {
        host: shost,
        port: datastore['RPORT'],
        proto: 'udp',
        name: 'ssdp'
      }
    }

    @results[skey][:info][:server] = Regexp.last_match(1).strip if data =~ /^Server:[\s]*(.*)/i

    ssdp_host = nil
    ssdp_port = 80
    location_string = ''
    if data =~ /^Location:[\s]*(.*)/i
      location_string = Regexp.last_match(1)
      @results[skey][:info][:location] = Regexp.last_match(1).strip
      if location_string[/(https?):\x2f\x2f([^\x5c\x2f]+)/]
        ssdp_host, ssdp_port = Regexp.last_match(2).split(":") if Regexp.last_match(2).respond_to?(:split)
        ssdp_port = (Regexp.last_match(1) == "http" ? 80 : 443) if ssdp_port.nil?

        if ssdp_host && ssdp_port
          @results[skey][:info][:ssdp_host] = ssdp_host
          @results[skey][:info][:ssdp_port] = ssdp_port.to_i
        end

      end
    end

    @results[skey][:info][:usn] = Regexp.last_match(1).strip if data =~ /^USN:[\s]*(.*)/i
  end
end
