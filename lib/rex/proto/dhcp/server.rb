# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/socket'
require 'rex/proto/dhcp'

module Rex
  module Proto
    module DHCP
      ##
      #
      # DHCP Server class
      # not completely configurable - written specifically for a PXE server
      # - scriptjunkie
      #
      # extended to support testing/exploiting CVE-2011-0997
      # - apconole@yahoo.com
      ##

      class Server
        include Rex::Socket

        def initialize(hash, context = {})
          self.listen_host = '0.0.0.0' # clients don't already have addresses. Needs to be 0.0.0.0
          self.listen_port = 67 # mandatory (bootps)
          self.context = context
          self.sock = nil

          self.myfilename = hash['FILENAME'] || ""
          myfilename << ("\x00" * (128 - myfilename.length))

          source = hash['SRVHOST'] || Rex::Socket.source_address
          self.ipstring = Rex::Socket.addr_aton(source)

          ipstart = hash['DHCPIPSTART']
          self.start_ip = if ipstart
                            Rex::Socket.addr_atoi(ipstart)
                          else
                            # Use the first 3 octects of the server's IP to construct the
                            # default range of x.x.x.32-254
                            "#{ipstring[0..2]}\x20".unpack("N").first
                          end
          self.current_ip = start_ip

          ipend = hash['DHCPIPEND']
          self.end_ip = if ipend
                          Rex::Socket.addr_atoi(ipend)
                        else
                          # Use the first 3 octects of the server's IP to construct the
                          # default range of x.x.x.32-254
                          "#{ipstring[0..2]}\xfe".unpack("N").first
                        end

          # netmask
          netmask = hash['NETMASK'] || "255.255.255.0"
          self.netmaskn = Rex::Socket.addr_aton(netmask)

          # router
          router = hash['ROUTER'] || source
          self.router = Rex::Socket.addr_aton(router)

          # dns
          dnsserv = hash['DNSSERVER'] || source
          self.dnsserv = Rex::Socket.addr_aton(dnsserv)

          # broadcast
          self.broadcasta = if hash['BROADCAST']
                              Rex::Socket.addr_aton(hash['BROADCAST'])
                            else
                              Rex::Socket.addr_itoa(start_ip | (Rex::Socket.addr_ntoi(netmaskn) ^ 0xffffffff))
                            end

          self.served = {}
          self.serveOnce = hash.include?('SERVEONCE')

          self.servePXE = (hash.include?('PXE') || hash.include?('FILENAME') || hash.include?('PXEONLY'))
          self.serveOnlyPXE = hash.include?('PXEONLY')

          # Always assume we don't give out hostnames ...
          self.give_hostname = false
          self.served_over = 0
          if hash['HOSTNAME']
            self.give_hostname = true
            self.served_hostname = hash['HOSTNAME']
            self.served_over = hash['HOSTSTART'].to_i if hash['HOSTSTART']
          end

          self.leasetime = 600
          self.relayip = "\x00\x00\x00\x00" # relay ip - not currently suported
          self.pxeconfigfile = "update2"
          self.pxealtconfigfile = "update0"
          self.pxepathprefix = ""
          self.pxereboottime = 2000

          self.domain_name = hash['DOMAINNAME'] || nil
          self.url = hash['URL'] if hash.include?('URL')
        end

        def report(&block)
          self.reporter = block
        end

        # Start the DHCP server
        def start
          self.sock = Rex::Socket::Udp.create(
            'LocalHost' => listen_host,
            'LocalPort' => listen_port,
            'Context'   => context
          )

          self.thread = Rex::ThreadFactory.spawn("DHCPServerMonitor", false) {
            monitor_socket
          }
        end

        # Stop the DHCP server
        def stop
          thread.kill
          self.served = {}
          begin
          sock.close
        rescue
          nil
        end
        end

        # Set an option
        def set_option(opts)
          allowed_options = [
            :serveOnce, :pxealtconfigfile, :servePXE, :relayip, :leasetime, :dnsserv,
            :pxeconfigfile, :pxepathprefix, :pxereboottime, :router,
            :give_hostname, :served_hostname, :served_over, :serveOnlyPXE, :domain_name, :url
          ]

          opts.each_pair do |k, v|
            next unless v
            instance_variable_set("@#{k}", v) if allowed_options.include?(k)
          end
        end

        # Send a single packet to the specified host
        def send_packet(ip, pkt)
          port = 68 # bootpc
          if ip
            sock.sendto(pkt, ip, port)
          else
            unless sock.sendto(pkt, '255.255.255.255', port)
              sock.sendto(pkt, broadcasta, port)
            end
          end
        end

        attr_accessor :listen_host, :listen_port, :context, :leasetime, :relayip, :router, :dnsserv
        attr_accessor :domain_name
        attr_accessor :sock, :thread, :myfilename, :ipstring, :served, :serveOnce
        attr_accessor :current_ip, :start_ip, :end_ip, :broadcasta, :netmaskn
        attr_accessor :servePXE, :pxeconfigfile, :pxealtconfigfile, :pxepathprefix, :pxereboottime, :serveOnlyPXE
        attr_accessor :give_hostname, :served_hostname, :served_over, :reporter, :url

        protected

        # See if there is anything to do.. If so, dispatch it.
        def monitor_socket
          loop do
            rds = [@sock]
            wds = []
            eds = [@sock]

            r, = ::IO.select(rds, wds, eds, 1)

            next unless !r.nil? && (r[0] == sock)
            buf, host, port = sock.recvfrom(65535)
            # Lame compatabilitiy :-/
            from = [host, port]
            dispatch_request(from, buf)
          end
        end

        def dhcpoption(type, val = nil)
          ret = ''
          ret << [type].pack('C')

          ret << [val.length].pack('C') + val if val

          ret
        end

        # Dispatch a packet that we received
        def dispatch_request(_from, buf)
          type = buf.unpack('C').first
          if type != Request
            # dlog("Unknown DHCP request type: #{type}")
            return
          end

          # parse out the members
          _hwtype = buf[1, 1]
          hwlen = buf[2, 1].unpack("C").first
          _hops = buf[3, 1]
          _txid = buf[4..7]
          _elapsed = buf[8..9]
          _flags = buf[10..11]
          clientip = buf[12..15]
          _givenip = buf[16..19]
          _nextip = buf[20..23]
          _relayip = buf[24..27]
          _clienthwaddr = buf[28..(27 + hwlen)]
          servhostname = buf[44..107]
          _filename = buf[108..235]
          magic = buf[236..239]

          if magic != DHCPMagic
            # dlog("Invalid DHCP request - bad magic.")
            return
          end

          messageType = 0
          pxeclient = false

          # options parsing loop
          spot = 240
          while spot < buf.length - 3
            optionType = buf[spot, 1].unpack("C").first
            break if optionType == 0xff

            optionLen = buf[spot + 1, 1].unpack("C").first
            optionValue = buf[(spot + 2)..(spot + optionLen + 1)]
            spot = spot + optionLen + 2
            if optionType == 53
              messageType = optionValue.unpack("C").first
            elsif (optionType == 150) || ((optionType == 60) && optionValue.include?("PXEClient"))
              pxeclient = true
            end
          end

          # don't serve if only serving PXE and not PXE request
          return if (pxeclient == false) && (serveOnlyPXE == true)

          # prepare response
          pkt = [Response].pack('C')
          pkt << buf[1..7] # hwtype, hwlen, hops, txid
          pkt << "\x00\x00\x00\x00" # elapsed, flags
          pkt << clientip

          # if this is somebody we've seen before, use the saved IP
          if served.include?(buf[28..43])
            pkt << Rex::Socket.addr_iton(served[buf[28..43]][0])
          else # otherwise go to next ip address
            self.current_ip += 1
            self.current_ip = start_ip if self.current_ip > end_ip
            served[buf[28..43]] = [ self.current_ip, messageType == DHCPRequest ]
            pkt << Rex::Socket.addr_iton(self.current_ip)
          end
          pkt << ipstring # next server ip
          pkt << relayip
          pkt << buf[28..43] # client hw address
          pkt << servhostname
          pkt << myfilename
          pkt << magic
          pkt << "\x35\x01" # Option

          if messageType == DHCPDiscover # DHCP Discover - send DHCP Offer
            pkt << [DHCPOffer].pack('C')
            # check if already served an Ack based on hw addr (MAC address)
            # if serveOnce & PXE, don't reply to another PXE request
            # if serveOnce & ! PXE, don't reply to anything
            if (serveOnce == true) && served.key?(buf[28..43]) &&
               served[buf[28..43]][1] && ((pxeclient == false) || (servePXE == false))
              return
            end
          elsif messageType == DHCPRequest # DHCP Request - send DHCP ACK
            pkt << [DHCPAck].pack('C')
            # now we ignore their discovers (but we'll respond to requests in case a packet was lost)
            if served_over != 0
              # NOTE: this is sufficient for low-traffic net
              # for high-traffic, this will probably lead to
              # hostname collision
              self.served_over += 1
            end
          else
            return # ignore unknown DHCP request
          end

          # Options!
          pkt << dhcpoption(OpDHCPServer, ipstring)
          pkt << dhcpoption(OpLeaseTime, [leasetime].pack('N'))
          pkt << dhcpoption(OpSubnetMask, netmaskn)
          pkt << dhcpoption(OpRouter, router)
          pkt << dhcpoption(OpDns, dnsserv)
          pkt << dhcpoption(OpDomainName, domain_name)

          if servePXE # PXE options
            pkt << dhcpoption(OpPXEMagic, PXEMagic)
            # We already got this one, serve localboot file
            if (serveOnce == true) && served.key?(buf[28..43]) &&
               served[buf[28..43]][1] && (pxeclient == true)
              pkt << dhcpoption(OpPXEConfigFile, pxealtconfigfile)
            else
              # We are handing out an IP and our PXE attack
              reporter&.call(buf[28..43], ipstring)
              pkt << dhcpoption(OpPXEConfigFile, pxeconfigfile)
            end
            pkt << dhcpoption(OpPXEPathPrefix, pxepathprefix)
            pkt << dhcpoption(OpPXERebootTime, [pxereboottime].pack('N'))
            if give_hostname == true
              send_hostname = served_hostname
              if self.served_over != 0
                # NOTE : see above comments for the 'uniqueness' of this value
                send_hostname += self.served_over.to_s
              end
              pkt << dhcpoption(OpHostname, send_hostname)
            end
          end
          pkt << dhcpoption(OpURL, url) if url
          pkt << dhcpoption(OpEnd)

          pkt << ("\x00" * 32) # padding

          # And now we mark as requested
          served[buf[28..43]][1] = true if messageType == DHCPRequest

          send_packet(nil, pkt)
        end
      end
    end
  end
end
