# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/tcp'

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  @@cached_rsa_key = nil

  def initialize
    super(
      'Name'        => 'VMWare Authentication Daemon Version Scanner',
      'Description' => %q(
        This module will identify information about a host through the
      vmauthd service.
      ),
      'Author'      => ['theLightCosine', 'hdm'],
      'License'     => MSF_LICENSE
    )

    register_options([Opt::RPORT(902)])
  end

  def run_host(_ip)
    begin

      begin
        connect
      rescue
        nil
      end
      return unless sock

      banner = sock.get_once(-1, 10)
      unless banner
        print_error "#{rhost}:#{rport} No banner received from vmauthd"
        return
      end

      banner = banner.strip

      unless banner =~ /VMware Authentication Daemon/
        print_error "#{rhost}:#{rport} This does not appear to be a vmauthd service"
        return
      end

      cert = nil

      if banner =~ /SSL/
        print_status("#{rhost}:#{rport} Switching to SSL connection...")
        swap_sock_plain_to_ssl
        cert = sock.peer_cert
      end

      banner << " Certificate:#{cert.subject}" if cert

      print_status "#{rhost}:#{rport} Banner: #{banner}"

      report_service(
        host: rhost,
        port: rport,
        sname: 'vmauthd',
        info: banner,
        proto: 'tcp'
      )

    rescue ::Interrupt
      raise $ERROR_INFO
    ensure
      disconnect
    end
  end

  def do_login(user, pass, nsock = sock)
    nsock.put("USER #{user}\r\n")
    res = nsock.get_once || ''
    unless res.start_with? "331"
      ret_msg = "Unexpected reply to the USER command: #{res}"
      return ret_msg
    end
    nsock.put("PASS #{pass}\r\n")
    res = nsock.get_once || ''
    if res.start_with? "530"
      return :failed
    elsif res.start_with? "230"
      return :success
    else
      ret_msg = "Unexpected reply to the PASS command: #{res}"
      return ret_msg
    end
  end

  def swap_sock_plain_to_ssl(nsock = sock)
    ctx = generate_ssl_context
    ssl = OpenSSL::SSL::SSLSocket.new(nsock, ctx)

    ssl.connect

    nsock.extend(Rex::Socket::SslTcp)
    nsock.sslsock = ssl
    nsock.sslctx  = ctx
  end

  def generate_ssl_context
    ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
    @@cached_rsa_key ||= OpenSSL::PKey::RSA.new(1024) {}

    ctx.key = @@cached_rsa_key

    ctx.session_id_context = Rex::Text.rand_text(16)

    ctx
  end
end
