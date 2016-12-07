# frozen_string_literal: true
# -*- coding: binary -*-
module Msf
  ###
  #
  # This module provides methods for working with Cisco equipment
  #
  ###
  module Auxiliary::Cisco
    include Msf::Auxiliary::Report

    def cisco_ios_decrypt7(inp)
      xlat = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
        0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
        0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
        0x55, 0x42
      ]

      return nil unless inp[0, 2] =~ /\d\d/

      seed  = nil
      clear = ""
      inp.scan(/../).each do |byte|
        unless seed
          seed = byte.to_i
          next
        end
        byte = byte.to_i(16)
        clear << [ byte ^ xlat[ seed ]].pack("C")
        seed += 1
      end
      clear
    end

    def create_credential_and_login(opts = {})
      return nil unless active_db?

      opts[:task_id] ||= self[:task].record.id if respond_to?(:[]) && self[:task]

      core               = opts.fetch(:core, create_credential(opts))
      access_level       = opts.fetch(:access_level, nil)
      last_attempted_at  = opts.fetch(:last_attempted_at, nil)
      status             = opts.fetch(:status, Metasploit::Model::Login::Status::UNTRIED)

      login_object = nil
      retry_transaction do
        service_object = create_credential_service(opts)
        login_object = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_object.id).first_or_initialize

        login_object.tasks << Mdm::Task.find(opts[:task_id]) if opts[:task_id]

        login_object.access_level      = access_level if access_level
        login_object.last_attempted_at = last_attempted_at if last_attempted_at
        if status == Metasploit::Model::Login::Status::UNTRIED
          login_object.status = status if login_object.last_attempted_at.nil?
        else
          login_object.status = status
        end
        login_object.save!
      end

      login_object
    end

    def cisco_ios_config_eater(thost, tport, config)
      credential_data = {
        address: thost,
        port: tport,
        protocol: 'tcp',
        workspace_id: myworkspace.id,
        origin_type: :service,
        service_name: '',
        module_fullname: fullname,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Default SNMP to UDP
      credential_data[:protocol] = 'udp' if tport == 161

      store_loot("cisco.ios.config", "text/plain", thost, config.strip, "config.txt", "Cisco IOS Configuration")

      tuniface = nil

      config.each_line do |line|
        case line
          #
          # Enable passwords
          #
        when /^\s*enable (password|secret) (\d+) (.*)/i
          stype = Regexp.last_match(2).to_i
          shash = Regexp.last_match(3).strip

          if stype == 5
            print_good("#{thost}:#{tport} MD5 Encrypted Enable Password: #{shash}")
            store_loot("cisco.ios.enable_hash", "text/plain", thost, shash, "enable_password_hash.txt", "Cisco IOS Enable Password Hash (MD5)")
            cred = credential_data.dup
            cred[:private_data] = shash
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Enable Password: #{shash}")
            store_loot("cisco.ios.enable_pass", "text/plain", thost, shash, "enable_password.txt", "Cisco IOS Enable Password")

            cred = credential_data.dup
            cred[:private_data] = shash
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)

          end

          if stype == 7
            shash = begin
                      cisco_ios_decrypt7(shash)
                    rescue
                      shash
                    end
            print_good("#{thost}:#{tport} Decrypted Enable Password: #{shash}")
            store_loot("cisco.ios.enable_pass", "text/plain", thost, shash, "enable_password.txt", "Cisco IOS Enable Password")

            cred = credential_data.dup
            cred[:private_data] = shash
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end

        when /^\s*enable password (.*)/i
          spass = Regexp.last_match(1).strip
          print_good("#{thost}:#{tport} Unencrypted Enable Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

          #
          # SNMP
          #
        when /^\s*snmp-server community ([^\s]+) (RO|RW)/i
          stype = Regexp.last_match(2).strip
          scomm = Regexp.last_match(1).strip
          print_good("#{thost}:#{tport} SNMP Community (#{stype}): #{scomm}")

          cred = credential_data.dup
          cred[:access_level] = if stype.casecmp("ro").zero?
                                  "RO"
                                else
                                  "RW"
                                end
          cred[:protocol] = "udp"
          cred[:port] = 161
          cred[:private_data] = scomm
          cred[:private_type] = :password
          create_credential_and_login(cred)
          #
          # VTY Passwords
          #
        when /^\s*password 7 ([^\s]+)/i
          spass = Regexp.last_match(1).strip
          spass = begin
                    cisco_ios_decrypt7(spass)
                  rescue
                    spass
                  end

          print_good("#{thost}:#{tport} Decrypted VTY Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :password
          create_credential_and_login(cred)

        when /^\s*(password|secret) 5 (.*)/i
          shash = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} MD5 Encrypted VTY Password: #{shash}")
          store_loot("cisco.ios.vty_password", "text/plain", thost, shash, "vty_password_hash.txt", "Cisco IOS VTY Password Hash (MD5)")

          cred = credential_data.dup
          cred[:private_data] = shash
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*password (0 |)([^\s]+)/i
          spass = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} Unencrypted VTY Password: #{spass}")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

          #
          # WiFi Passwords
          #
        when /^\s*encryption key \d+ size \d+bit (\d+) ([^\s]+)/
          spass = Regexp.last_match(2).strip
          print_good("#{thost}:#{tport} Wireless WEP Key: #{spass}")
          store_loot("cisco.ios.wireless_wep", "text/plain", thost, spass, "wireless_wep.txt", "Cisco IOS Wireless WEP Key")

        when /^\s*wpa-psk (ascii|hex) (\d+) ([^\s]+)/i

          stype = Regexp.last_match(2).to_i
          spass = Regexp.last_match(3).strip

          if stype == 5
            print_good("#{thost}:#{tport} Wireless WPA-PSK MD5 Password Hash: #{spass}")
            store_loot("cisco.ios.wireless_wpapsk_hash", "text/plain", thost, spass, "wireless_wpapsk_hash.txt", "Cisco IOS Wireless WPA-PSK Password Hash (MD5)")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Wireless WPA-PSK Password: #{spass}")
            store_loot("cisco.ios.wireless_wpapsk", "text/plain", thost, spass, "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Password")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = begin
                      cisco_ios_decrypt7(spass)
                    rescue
                      spass
                    end
            print_good("#{thost}:#{tport} Wireless WPA-PSK Decrypted Password: #{spass}")
            store_loot("cisco.ios.wireless_wpapsk", "text/plain", thost, spass, "wireless_wpapsk.txt", "Cisco IOS Wireless WPA-PSK Decrypted Password")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end

          #
          # VPN Passwords
          #
        when /^\s*crypto isakmp key ([^\s]+) address ([^\s]+)/i
          spass = Regexp.last_match(1)
          shost = Regexp.last_match(2)

          print_good("#{thost}:#{tport} VPN IPSEC ISAKMP Key '#{spass}' Host '#{shost}'")
          store_loot("cisco.ios.vpn_ipsec_key", "text/plain", thost, spass.to_s, "vpn_ipsec_key.txt", "Cisco VPN IPSEC Key")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*interface tunnel(\d+)/i
          tuniface = Regexp.last_match(1)

        when /^\s*tunnel key ([^\s]+)/i
          spass = Regexp.last_match(1)
          siface = tuniface

          print_good("#{thost}:#{tport} GRE Tunnel Key #{spass} for Interface Tunnel #{siface}")
          store_loot("cisco.ios.gre_tunnel_key", "text/plain", thost, "tunnel#{siface}_#{spass}", "gre_tunnel_key.txt", "Cisco GRE Tunnel Key")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

        when /^\s*ip nhrp authentication ([^\s]+)/i
          spass = Regexp.last_match(1)
          siface = tuniface

          print_good("#{thost}:#{tport} NHRP Authentication Key #{spass} for Interface Tunnel #{siface}")
          store_loot("cisco.ios.nhrp_tunnel_key", "text/plain", thost, "tunnel#{siface}_#{spass}", "nhrp_tunnel_key.txt", "Cisco NHRP Authentication Key")

          cred = credential_data.dup
          cred[:private_data] = spass
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)

          #
          # Various authentication secrets
          #
        when /^\s*username ([^\s]+) privilege (\d+) (secret|password) (\d+) ([^\s]+)/i
          user  = Regexp.last_match(1)
          priv  = Regexp.last_match(2)
          stype = Regexp.last_match(4).to_i
          spass = Regexp.last_match(5)

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            store_loot("cisco.ios.username_password_hash", "text/plain", thost, "#{user}_level#{priv}:#{spass}", "username_password_hash.txt", "Cisco IOS Username and Password Hash (MD5)")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}_level#{priv}:#{spass}", "username_password.txt", "Cisco IOS Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = begin
                      cisco_ios_decrypt7(spass)
                    rescue
                      spass
                    end
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}_level#{priv}:#{spass}", "username_password.txt", "Cisco IOS Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end

        when /^\s*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i
          user  = Regexp.last_match(1)
          stype = Regexp.last_match(3).to_i
          spass = Regexp.last_match(4)

          if stype == 5
            print_good("#{thost}:#{tport} Username '#{user}' with MD5 Encrypted Password: #{spass}")
            store_loot("cisco.ios.username_password_hash", "text/plain", thost, "#{user}:#{spass}", "username_password_hash.txt", "Cisco IOS Username and Password Hash (MD5)")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Username '#{user}' with Password: #{spass}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}:#{spass}", "username_password.txt", "Cisco IOS Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = begin
                      cisco_ios_decrypt7(spass)
                    rescue
                      spass
                    end
            print_good("#{thost}:#{tport} Username '#{user}' with Decrypted Password: #{spass}")
            store_loot("cisco.ios.username_password", "text/plain", thost, "#{user}:#{spass}", "username_password.txt", "Cisco IOS Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end

        when /^\s*ppp.*username ([^\s]+) (secret|password) (\d+) ([^\s]+)/i

          suser = Regexp.last_match(1)
          stype = Regexp.last_match(3).to_i
          spass = Regexp.last_match(4)

          if stype == 5
            print_good("#{thost}:#{tport} PPP Username #{suser} MD5 Encrypted Password: #{spass}")
            store_loot("cisco.ios.ppp_username_password_hash", "text/plain", thost, "#{suser}:#{spass}", "ppp_username_password_hash.txt", "Cisco IOS PPP Username and Password Hash (MD5)")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} PPP Username: #{suser} Password: #{spass}")
            store_loot("cisco.ios.ppp_username_password", "text/plain", thost, "#{suser}:#{spass}", "ppp_username_password.txt", "Cisco IOS PPP Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = begin
                      cisco_ios_decrypt7(spass)
                    rescue
                      spass
                    end
            print_good("#{thost}:#{tport} PPP Username: #{suser} Decrypted Password: #{spass}")
            store_loot("cisco.ios.ppp_username_password", "text/plain", thost, "#{suser}:#{spass}", "ppp_username_password.txt", "Cisco IOS PPP Username and Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end

        when /^\s*ppp chap (secret|password) (\d+) ([^\s]+)/i
          stype = Regexp.last_match(2).to_i
          spass = Regexp.last_match(3)

          if stype == 5
            print_good("#{thost}:#{tport} PPP CHAP MD5 Encrypted Password: #{spass}")
            store_loot("cisco.ios.ppp_password_hash", "text/plain", thost, spass, "ppp_password_hash.txt", "Cisco IOS PPP Password Hash (MD5)")
            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 0
            print_good("#{thost}:#{tport} Password: #{spass}")
            store_loot("cisco.ios.ppp_password", "text/plain", thost, spass, "ppp_password.txt", "Cisco IOS PPP Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :nonreplayable_hash
            create_credential_and_login(cred)
          end

          if stype == 7
            spass = begin
                      cisco_ios_decrypt7(spass)
                    rescue
                      spass
                    end
            print_good("#{thost}:#{tport} PPP Decrypted Password: #{spass}")
            store_loot("cisco.ios.ppp_password", "text/plain", thost, spass, "ppp_password.txt", "Cisco IOS PPP Password")

            cred = credential_data.dup
            cred[:private_data] = spass
            cred[:private_type] = :password
            create_credential_and_login(cred)
          end
        end
      end
    end
  end
end
