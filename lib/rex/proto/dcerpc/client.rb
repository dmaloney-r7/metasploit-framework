# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Proto
    module DCERPC
      class Client
        require 'rex/proto/dcerpc/uuid'
        require 'rex/proto/dcerpc/response'
        require 'rex/proto/dcerpc/exceptions'
        require 'rex/text'
        require 'rex/proto/smb/exceptions'

        attr_accessor :handle, :socket, :options, :last_response, :context, :no_bind, :ispipe, :smb

        # initialize a DCE/RPC Function Call
        def initialize(handle, socket, useroptions = {})
          self.handle = handle
          self.socket = socket
          self.options = {
            'smb_user'   => '',
            'smb_pass'   => '',
            'smb_pipeio' => 'rw',
            'smb_name'   => nil,
            'read_timeout'    => 10,
            'connect_timeout' => 5
          }

          options.merge!(useroptions)

          # If the caller passed us a smb_client object, use it and
          # and skip the connect/login/ipc$ stages of the setup
          self.smb = options['smb_client'] if options['smb_client']

          # we must have a valid handle, regardless of everything else
          raise ArgumentError, 'handle is not a Rex::Proto::DCERPC::Handle' unless self.handle.is_a?(Rex::Proto::DCERPC::Handle)

          # we do this in case socket needs setup first, ie, socket = nil
          socket_check unless options['no_socketsetup']

          raise ArgumentError, 'socket can not read' unless self.socket.respond_to?(:read)
          raise ArgumentError, 'socket can not write' unless self.socket.respond_to?(:write)

          bind unless options['no_autobind']
        end

        def socket_check
          socket_setup if socket.nil?

          case handle.protocol
          when 'ncacn_ip_tcp'
            if socket.type? != 'tcp'
              raise ::Rex::Proto::DCERPC::Exceptions::InvalidSocket, "ack, #{handle.protocol} requires socket type tcp, not #{socket.type?}!"
            end
          when 'ncacn_np'
            if socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
              self.ispipe = 1
            elsif socket.type? == 'tcp'
              smb_connect
            else
              raise ::Rex::Proto::DCERPC::Exceptions::InvalidSocket, "ack, #{handle.protocol} requires socket type tcp, not #{socket.type?}!"
            end
          # No support ncacn_ip_udp (is it needed now that its ripped from Vista?)
          else
            raise ::Rex::Proto::DCERPC::Exceptions::InvalidSocket, "Unsupported protocol : #{handle.protocol}"
          end
        end

        # Create the appropriate socket based on protocol
        def socket_setup
          ctx = { 'Msf' => options['Msf'], 'MsfExploit' => options['MsfExploit'] }
          self.socket = case handle.protocol

                        when 'ncacn_ip_tcp'
                          Rex::Socket.create_tcp(
                            'PeerHost' => handle.address,
                            'PeerPort' => handle.options[0],
                            'Context' => ctx,
                            'Timeout' => options['connect_timeout']
                          )

                        when 'ncacn_np'
                          begin
                            socket = Rex::Socket.create_tcp(
                              'PeerHost' => handle.address,
                              'PeerPort' => 445,
                              'Context' => ctx,
                              'Timeout' => options['connect_timeout']
                            )
                          rescue ::Timeout::Error, Rex::ConnectionRefused
                            socket = Rex::Socket.create_tcp(
                              'PeerHost' => handle.address,
                              'PeerPort' => 139,
                              'Context' => ctx,
                              'Timeout' => options['connect_timeout']
                            )
                          end
                          socket
            end

          # Add this socket to the exploit's list of open sockets
          options['MsfExploit']&.add_socket(self.socket)
        end

        def smb_connect
          require 'rex/proto/smb/simpleclient'

          unless smb
            smb = if socket.peerport == 139
                    Rex::Proto::SMB::SimpleClient.new(socket)
                  else
                    Rex::Proto::SMB::SimpleClient.new(socket, true)
                  end

            smb.login('*SMBSERVER', options['smb_user'], options['smb_pass'])
            smb.connect("\\\\#{handle.address}\\IPC$")
            self.smb = smb
            self.smb.read_timeout = options['read_timeout']
          end

          f = self.smb.create_pipe(handle.options[0])
          f.mode = options['smb_pipeio']
          self.socket = f
        end

        def read
          max_read = options['pipe_read_max_size'] || 1024 * 1024
          min_read = options['pipe_read_min_size'] || max_read

          raw_response = ''

          # Are we reading from a remote pipe over SMB?
          if socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
            begin

              # Max SMB read is 65535, cap it at 64000
              max_read = [64000, max_read].min
              min_read = [64000, min_read].min

              read_limit = nil

              loop do
                # Random read offsets will not work on Windows NT 4.0 (thanks Dave!)

                read_cnt = (rand(max_read - min_read) + min_read)
                if read_limit
                  if read_cnt + raw_response.length > read_limit
                    read_cnt = raw_response.length - read_limit
                  end
                end

                data = socket.read(read_cnt, rand(1024) + 1)
                break unless data && !data.empty?
                raw_response += data

                # Keep reading until we have at least the DCERPC header
                next if raw_response.length < 10

                # We now have to process the raw_response and parse out the DCERPC fragment length
                # if we have read enough data. Once we have the length value, we need to make sure
                # that we don't read beyond this amount, or it can screw up the SMB state
                unless read_limit
                  begin
                    check = Rex::Proto::DCERPC::Response.new(raw_response)
                    read_limit = check.frag_len
                  rescue ::Rex::Proto::DCERPC::Exceptions::InvalidPacket
                  end
                end
                break if read_limit && (read_limit <= raw_response.length)
              end

            rescue Rex::Proto::SMB::Exceptions::NoReply
              # I don't care if I didn't get a reply...
            rescue Rex::Proto::SMB::Exceptions::ErrorCode => exception
              raise exception if exception.error_code != 0xC000014B
            end
          # This must be a regular TCP or UDP socket
          else
            if socket.type? == 'tcp'
              if false && max_read
                loop do
                  data = socket.get_once((rand(max_read - min_read) + min_read), options['read_timeout'])
                  break unless data
                  break unless data.length
                  raw_response << data
                end
              else
                # Just read the entire response in one go
                raw_response = socket.get_once(-1, options['read_timeout'])
              end
            else
              # No segmented read support for non-TCP sockets
              raw_response = socket.read(0xFFFFFFFF / 2 - 1) # read max data
            end
          end

          raw_response
        end

        # Write data to the underlying socket, limiting the sizes of the writes based on
        # the pipe_write_min / pipe_write_max options.
        def write(data)
          max_write = options['pipe_write_max_size'] || data.length
          min_write = options['pipe_write_min_size'] || max_write

          max_write = min_write if min_write > max_write

          idx = 0

          if socket.class == Rex::Proto::SMB::SimpleClient::OpenPipe
            while idx < data.length
              bsize = (rand(max_write - min_write) + min_write).to_i
              len = socket.write(data[idx, bsize], rand(1024) + 1)
              idx += bsize
            end
          else
            socket.write(data)
          end

          data.length
        end

        def bind
          require 'rex/proto/dcerpc/packet'
          bind = ''
          context = ''
          if options['fake_multi_bind']

            args = [ handle.uuid[0], handle.uuid[1] ]

            if options['fake_multi_bind_prepend']
              args << options['fake_multi_bind_prepend']
            end

            if options['fake_multi_bind_append']
              args << options['fake_multi_bind_append']
            end

            bind, context = Rex::Proto::DCERPC::Packet.make_bind_fake_multi(*args)
          else
            bind, context = Rex::Proto::DCERPC::Packet.make_bind(*handle.uuid)
          end

          raise ::Rex::Proto::DCERPC::Exceptions::BindError, 'make_bind failed' unless bind

          write(bind)
          raw_response = read

          response = Rex::Proto::DCERPC::Response.new(raw_response)
          self.last_response = response
          if (response.type == 12) || (response.type == 15)
            if last_response.ack_result[context] == 2
              raise ::Rex::Proto::DCERPC::Exceptions::BindError, "Could not bind to #{handle}"
            end
            self.context = context
          else
            raise ::Rex::Proto::DCERPC::Exceptions::BindError, "Could not bind to #{handle}"
          end
        end

        # Perform a DCE/RPC Function Call
        def call(function, data, do_recv = true)
          frag_size = data.length
          frag_size = options['frag_size'] if options['frag_size']
          object_id = ''
          object_id = handle.uuid[0] if options['object_call']
          if options['random_object_id']
            object_id = Rex::Proto::DCERPC::UUID.uuid_unpack(Rex::Text.rand_text(16))
          end

          call_packets = Rex::Proto::DCERPC::Packet.make_request(function, data, frag_size, context, object_id)
          call_packets.each do |packet|
            write(packet)
          end

          return true unless do_recv

          raw_response = ''

          begin
            raw_response = read
          rescue ::EOFError
            raise Rex::Proto::DCERPC::Exceptions::NoResponse
          end

          if raw_response.nil? || raw_response.empty?
            raise Rex::Proto::DCERPC::Exceptions::NoResponse
          end

          self.last_response = Rex::Proto::DCERPC::Response.new(raw_response)

          if last_response.type == 3
            e = Rex::Proto::DCERPC::Exceptions::Fault.new
            e.fault = last_response.status
            raise e
          end

          last_response.stub_data
        end

        # Process a DCERPC response packet from a socket
        def self.read_response(socket, timeout = options['read_timeout'])
          data = socket.get_once(-1, timeout)

          # We need at least 10 bytes to find the FragLen
          return if !data || data.length < 10

          # Pass the first 10 bytes to the constructor
          resp = Rex::Proto::DCERPC::Response.new(data.slice!(0, 10))

          # Something went wrong in the parser...
          return resp unless resp.frag_len

          # Do we need to read more data?
          if resp.frag_len > (data.length + 10)
            begin
              data << socket.timed_read(resp.frag_len - data.length - 10, timeout)
            rescue Timeout::Error
            end
          end

          # Still missing some data...
          if data.length != resp.frag_len - 10
            # TODO: Bubble this up somehow
            # $stderr.puts "Truncated DCERPC response :-("
            return resp
          end

          resp.parse(data)
          resp
        end
      end
    end
  end
end
