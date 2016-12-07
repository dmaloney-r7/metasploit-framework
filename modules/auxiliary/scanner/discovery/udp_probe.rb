# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Module::Deprecated

  deprecated(Date.new(2016, 11, 23), 'auxiliary/scanner/discovery/udp_sweep')

  def initialize
    super(
      'Name'        => 'UDP Service Prober',
      'Description' => 'Detect common UDP services using sequential probes',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::CHOST
      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_PORTS', [false, 'Randomize the order the ports are probed', true])
      ], self.class
    )

    # Intialize the probes array
    @probes = []

    # Add the UDP probe method names
    @probes << 'probe_pkt_dns'
    @probes << 'probe_pkt_netbios'
    @probes << 'probe_pkt_portmap'
    @probes << 'probe_pkt_mssql'
    @probes << 'probe_pkt_ntp'
    @probes << 'probe_pkt_snmp1'
    @probes << 'probe_pkt_snmp2'
    @probes << 'probe_pkt_sentinel'
    @probes << 'probe_pkt_db2disco'
    @probes << 'probe_pkt_citrix'
    @probes << 'probe_pkt_pca_st'
    @probes << 'probe_pkt_pca_nq'
    @probes << 'probe_chargen'
  end

  def setup
    super

    @probes = @probes.sort_by { rand } if datastore['RANDOMIZE_PORTS']
  end

  # Fingerprint a single host
  def run_host(ip)
    @results = {}
    @thost = ip

    begin
      udp_sock = nil

      @probes.each do |probe|
        # Send each probe to each host

        begin
          data, port = send(probe, ip)
          @tport = port

          # Create an unbound UDP socket if no CHOST is specified, otherwise
          # create a UDP socket bound to CHOST (in order to avail of pivoting)
          udp_sock = Rex::Socket::Udp.create('LocalHost' => datastore['CHOST'] || nil,
                                             'PeerHost' => ip, 'PeerPort' => port,
                                             'Context' => { 'Msf' => framework, 'MsfExploit' => self })

          udp_sock.put(data)

          (r = udp_sock.recvfrom(65535, 0.1)) && r[1]
          parse_reply(r) if r

        rescue ::Interrupt
          raise $ERROR_INFO
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused, ::IOError
          nil
        ensure
          udp_sock&.close
        end
      end
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Exception => e
      print_error("Unknown error: #{@thost}:#{@tport} #{e.class} #{e} #{e.backtrace}")
    end

    @results.each_key do |k|
      next unless @results[k].respond_to?('keys')
      data = @results[k]

      next unless inside_workspace_boundary?(data[:host])

      conf = {
        host: data[:host],
        port: data[:port],
        proto: 'udp',
        name: data[:app],
        info: data[:info]
      }

      conf[:host_name] = data[:hname].downcase if data[:hname]

      conf[:mac] = data[:mac].downcase if data[:mac]

      report_service(conf)
      print_status("Discovered #{data[:app]} on #{k} (#{data[:info]})")
    end
  end

  #
  # The response parsers
  #
  def parse_reply(pkt)
    # Ignore "empty" packets
    return unless pkt[1]

    pkt[1] = pkt[1].sub(/^::ffff:/, '') if pkt[1] =~ /^::ffff:/

    app = 'unknown'
    inf = ''
    maddr = nil
    hname = nil

    hkey = "#{pkt[1]}:#{pkt[2]}"

    # Work with protocols that return different data in different packets
    # These are reported at the end of the scanning loop to build state
    case pkt[2]
    when 5632

      @results[hkey] ||= {}
      data = @results[hkey]
      data[:app]  = "pcAnywhere_stat"
      data[:port] = pkt[2]
      data[:host] = pkt[1]

      case pkt[0]

      when /^NR(........................)(........)/
        name = Regexp.last_match(1).dup
        caps = Regexp.last_match(2).dup
        name = name.gsub(/_+$/, '').delete("\x00").strip
        caps = caps.gsub(/_+$/, '').delete("\x00").strip
        data[:name] = name
        data[:caps] = caps

      when /^ST(.+)/
        buff = Regexp.last_match(1).dup
        stat = 'Unknown'

        stat = "Available" if buff[2, 1].unpack("C")[0] == 67

        stat = "Busy" if buff[2, 1].unpack("C")[0] == 11

        data[:stat] = stat
      end

      inf << "Name: #{data[:name]} " if data[:name]

      inf << "- #{data[:stat]} " if data[:stat]

      inf << "( #{data[:caps]} ) " if data[:caps]
      data[:info] = inf
    end

    # Ignore duplicates for the protocols below
    return if @results[hkey]

    case pkt[2]

    when 19
      app = 'chargen'
      return unless chargen_parse(pkt[0])
      @results[hkey] = true

    when 53
      app = 'DNS'
      ver = nil

      if !ver && pkt[0] =~ /([6789]\.[\w\.\-_\:\(\)\[\]\/\=\+\|\{\}]+)/i
        ver = 'BIND ' + Regexp.last_match(1)
      end

      ver = 'Microsoft DNS' if !ver && (pkt[0][2, 4] == "\x81\x04\x00\x01")
      ver = 'TinyDNS'       if !ver && (pkt[0][2, 4] == "\x81\x81\x00\x01")

      ver = pkt[0].unpack('H*')[0] unless ver
      inf = ver if ver
      @results[hkey] = true

    when 137
      app = 'NetBIOS'

      data = pkt[0]

      head = data.slice!(0, 12)

      xid, flags, quests, answers, auths, adds = head.unpack('n6')
      return if quests != 0
      return if answers == 0

      qname = data.slice!(0, 34)
      rtype, rclass, rttl, rlen = data.slice!(0, 10).unpack('nnNn')
      buff = data.slice!(0, rlen)

      names = []

      case rtype
      when 0x21
        rcnt = buff.slice!(0, 1).unpack("C")[0]
        1.upto(rcnt) do
          tname = buff.slice!(0, 15).gsub(/\x00.*/, '').strip
          ttype = buff.slice!(0, 1).unpack("C")[0]
          tflag = buff.slice!(0, 2).unpack('n')[0]
          names << [ tname, ttype, tflag ]
        end
        maddr = buff.slice!(0, 6).unpack("C*").map { |c| "%.2x" % c }.join(":")

        names.each do |name|
          inf << name[0]
          inf << ":<%.2x>" % name[1]
          inf << if name[2] & 0x8000 == 0
                   ":U :"
                 else
                   ":G :"
                 end
        end
        inf << maddr

        hname = names[0][0] unless names.empty?
      end

      @results[hkey] = true

    when 111
      app = 'Portmap'
      buf = pkt[0]
      inf = ""
      hed = buf.slice!(0, 24)
      svc = []
      while buf.length >= 20
        rec = buf.slice!(0, 20).unpack("N5")
        svc << "#{rec[1]} v#{rec[2]} #{rec[3] == 0x06 ? 'TCP' : 'UDP'}(#{rec[4]})"
        report_service(
          host: pkt[1],
          port: rec[4],
          proto: (rec[3] == 0x06 ? "tcp" : "udp"),
          name: "sunrpc",
          info: "#{rec[1]} v#{rec[2]}"
        )
      end
      inf = svc.join(", ")
      @results[hkey] = true

    when 123
      app = 'NTP'
      ver = nil
      ver = pkt[0].unpack('H*')[0]
      ver = 'NTP v3'                  if ver =~ /^1c06|^1c05/
      ver = 'NTP v4'                  if ver =~ /^240304/
      ver = 'NTP v4 (unsynchronized)' if ver =~ /^e40/
      ver = 'Microsoft NTP'           if ver =~ /^dc00|^dc0f/
      inf = ver if ver
      @results[hkey] = true

    when 1434
      app = 'MSSQL'
      mssql_ping_parse(pkt[0]).each_pair do |k, v|
        inf += k + '=' + v + ' '
      end
      @results[hkey] = true

    when 161
      app = 'SNMP'

      asn = begin
              OpenSSL::ASN1.decode(pkt[0])
            rescue
              nil
            end
      return unless asn

      snmp_error = begin
                     asn.value[0].value
                   rescue
                     nil
                   end
      snmp_comm  = begin
                     asn.value[1].value
                   rescue
                     nil
                   end
      snmp_data  = begin
                     asn.value[2].value[3].value[0]
                   rescue
                     nil
                   end
      snmp_oid   = begin
                     snmp_data.value[0].value
                   rescue
                     nil
                   end
      snmp_info  = begin
                     snmp_data.value[1].value
                   rescue
                     nil
                   end

      return unless snmp_error && snmp_comm && snmp_data && snmp_oid && snmp_info
      snmp_info = snmp_info.to_s.gsub(/\s+/, ' ')

      inf = snmp_info
      com = snmp_comm
      @results[hkey] = true

    when 5093
      app = 'Sentinel'
      @results[hkey] = true

    when 523
      app = 'ibm-db2'
      inf = db2disco_parse(pkt[0])
      @results[hkey] = true

    when 1604
      app = 'citrix-ica'
      return unless citrix_parse(pkt[0])
      @results[hkey] = true

    end

    return unless inside_workspace_boundary?(pkt[1])
    report_service(
      host: pkt[1],
      mac: maddr && (maddr != '00:00:00:00:00:00') ? maddr : nil,
      host_name: hname ? hname.downcase : nil,
      port: pkt[2],
      proto: 'udp',
      name: app,
      info: inf
    )

    print_status("Discovered #{app} on #{pkt[1]}:#{pkt[2]} (#{inf})")
  end

  #
  # Parse a db2disco packet.
  #
  def db2disco_parse(data)
    res = data.split("\x00")
    "#{res[2]}_#{res[1]}"
  end

  #
  # Validate a chargen packet.
  #
  def chargen_parse(data)
    data =~ /ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789/i
  end

  #
  # Validate this is truly Citrix ICA; returns true or false.
  #
  def citrix_parse(data)
    server_response = "\x30\x00\x02\x31\x02\xfd\xa8\xe3\x02\x00\x06\x44" # Server hello response
    data =~ /^#{server_response}/
  end

  #
  # Parse a 'ping' response and format as a hash
  #
  def mssql_ping_parse(data)
    res = {}
    var = nil
    idx = data.index('ServerName')
    return res unless idx

    data[idx, data.length - idx].split(';').each do |d|
      if !var
        var = d
      else
        unless var.empty?
          res[var] = d
          var = nil
        end
      end
    end

    res
  end

  #
  # The probe definitions
  #

  def probe_chargen(_ip)
    pkt = Rex::Text.rand_text_alpha_lower(1)
    [pkt, 19]
  end

  def probe_pkt_dns(_ip)
    data = [rand(0xffff)].pack('n') +
           "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"\
           "\x07" + "VERSION"\
           "\x04" + "BIND"\
           "\x00\x00\x10\x00\x03"

    [data, 53]
  end

  def probe_pkt_netbios(_ip)
    data =
      [rand(0xffff)].pack('n') +
      "\x00\x00\x00\x01\x00\x00\x00\x00"\
      "\x00\x00\x20\x43\x4b\x41\x41\x41"\
      "\x41\x41\x41\x41\x41\x41\x41\x41"\
      "\x41\x41\x41\x41\x41\x41\x41\x41"\
      "\x41\x41\x41\x41\x41\x41\x41\x41"\
      "\x41\x41\x41\x00\x00\x21\x00\x01"

    [data, 137]
  end

  def probe_pkt_portmap(_ip)
    data =
      [
        rand(0xffffffff), # XID
        0,              # Type
        2,              # RPC Version
        100000,         # Program ID
        2,              # Program Version
        4,              # Procedure
        0, 0,   # Credentials
        0, 0,   # Verifier
      ].pack('N*')

    [data, 111]
  end

  def probe_pkt_mssql(_ip)
    ["\x02", 1434]
  end

  def probe_pkt_ntp(_ip)
    data =
      "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00" \
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
      "\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"
    [data, 123]
  end

  def probe_pkt_sentinel(_ip)
    ["\x7a\x00\x00\x00\x00\x00", 5093]
  end

  def probe_pkt_snmp1(_ip)
    version = 1
    data = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Integer(version - 1),
                                     OpenSSL::ASN1::OctetString("public"),
                                     OpenSSL::ASN1::Set.new([
                                                              OpenSSL::ASN1::Integer(rand(0x80000000)),
                                                              OpenSSL::ASN1::Integer(0),
                                                              OpenSSL::ASN1::Integer(0),
                                                              OpenSSL::ASN1::Sequence([
                                                                                        OpenSSL::ASN1::Sequence([
                                                                                                                  OpenSSL::ASN1.ObjectId("1.3.6.1.2.1.1.1.0"),
                                                                                                                  OpenSSL::ASN1.Null(nil)
                                                                                                                ])
                                                                                      ])
                                                            ], 0, :IMPLICIT)
                                   ]).to_der
    [data, 161]
  end

  def probe_pkt_snmp2(_ip)
    version = 2
    data = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Integer(version - 1),
                                     OpenSSL::ASN1::OctetString("public"),
                                     OpenSSL::ASN1::Set.new([
                                                              OpenSSL::ASN1::Integer(rand(0x80000000)),
                                                              OpenSSL::ASN1::Integer(0),
                                                              OpenSSL::ASN1::Integer(0),
                                                              OpenSSL::ASN1::Sequence([
                                                                                        OpenSSL::ASN1::Sequence([
                                                                                                                  OpenSSL::ASN1.ObjectId("1.3.6.1.2.1.1.1.0"),
                                                                                                                  OpenSSL::ASN1.Null(nil)
                                                                                                                ])
                                                                                      ])
                                                            ], 0, :IMPLICIT)
                                   ]).to_der
    [data, 161]
  end

  def probe_pkt_db2disco(_ip)
    data = "DB2GETADDR\x00SQL05000\x00"
    [data, 523]
  end

  def probe_pkt_citrix(_ip) # Server hello packet from citrix_published_bruteforce
    data =
      "\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00" \
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
      "\x00\x00\x00\x00"
    [data, 1604]
  end

  def probe_pkt_pca_st(_ip)
    ["ST", 5632]
  end

  def probe_pkt_pca_nq(_ip)
    ["NQ", 5632]
  end
end
