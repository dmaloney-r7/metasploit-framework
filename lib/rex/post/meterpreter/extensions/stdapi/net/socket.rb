# frozen_string_literal: true
# -*- coding: binary -*-

require 'thread'
require 'rex/socket'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/tcp_client_channel'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/tcp_server_channel'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/udp_channel'
require 'rex/logging'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Net
            ###
            #
            # This class provides an interface to interacting with sockets
            # on the remote machine.  It allows callers to open TCP, UDP,
            # and other arbitrary socket-based connections as channels that
            # can then be interacted with through the established
            # meterpreter connection.
            #
            ###
            class Socket
              ##
              #
              # Constructor
              #
              ##

              #
              # Initialize the socket subsystem and start monitoring sockets as they come
              # in.
              #
              def initialize(client)
                self.client = client

                # register the inbound handler for the tcp server channel (allowing us to
                # receive new client connections to a tcp server channel)
                client.register_inbound_handler(Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::TcpServerChannel)
              end

              #
              # Deregister the inbound handler for the tcp server channel
              #
              def shutdown
                client.deregister_inbound_handler(Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::TcpServerChannel)
              end

              ##
              #
              # Factory
              #
              ##

              #
              # Creates an arbitrary client socket channel using the information supplied
              # in the socket parameters instance.  The +params+ argument is expected to be
              # of type Rex::Socket::Parameters.
              #
              def create(params)
                res = nil

                if params.tcp?
                  res = if params.server?
                          create_tcp_server_channel(params)
                        else
                          create_tcp_client_channel(params)
                        end
                elsif params.udp?
                  res = create_udp_channel(params)
                end

                res
              end

              #
              # Create a TCP server channel.
              #
              def create_tcp_server_channel(params)
                return SocketSubsystem::TcpServerChannel.open(client, params)
              rescue ::Rex::Post::Meterpreter::RequestError => e
                case e.code
                when 10048
                  raise ::Rex::AddressInUse.new(params.localhost, params.localport)
                when 10000..10100
                  raise Rex::ConnectionError
                end
                raise e
              end

              #
              # Creates a TCP client channel.
              #
              def create_tcp_client_channel(params)
                channel = SocketSubsystem::TcpClientChannel.open(client, params)
                return channel.lsock unless channel.nil?
                return nil
              rescue ::Rex::Post::Meterpreter::RequestError => e
                case e.code
                when 10000..10100
                  raise Rex::ConnectionError
                end
                raise e
              end

              #
              # Creates a UDP channel.
              #
              def create_udp_channel(params)
                channel = SocketSubsystem::UdpChannel.open(client, params)
                return channel.lsock unless channel.nil?
                return nil
              rescue ::Rex::Post::Meterpreter::RequestError => e
                case e.code
                when 10048
                  raise ::Rex::AddressInUse.new(params.localhost, params.localport)
                when 10000..10100
                  raise Rex::ConnectionError
                end
                raise e
              end

              protected

              attr_accessor :client # :nodoc:
            end
          end; end; end; end; end; end
