# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex'

module Net
  module SSH
    class CommandStream
      attr_accessor :channel, :thread, :error, :ssh
      attr_accessor :lsock, :rsock, :monitor

      module PeerInfo
        include ::Rex::IO::Stream
        attr_accessor :peerinfo
        attr_accessor :localinfo
      end

      def initialize(ssh, cmd, cleanup = false)
        self.lsock, self.rsock = Rex::Socket.tcp_socket_pair
        lsock.extend(Rex::IO::Stream)
        lsock.extend(PeerInfo)
        rsock.extend(Rex::IO::Stream)

        self.ssh = ssh
        self.thread = Thread.new(ssh, cmd, cleanup) do |rssh, rcmd, rcleanup|
          begin
            info = rssh.transport.socket.getpeername_as_array
            lsock.peerinfo = "#{info[1]}:#{info[2]}"

            info = rssh.transport.socket.getsockname
            lsock.localinfo = "#{info[1]}:#{info[2]}"

            rssh.open_channel do |rch|
              rch.exec(rcmd) do |c, success|
                raise "could not execute command: #{rcmd.inspect}" unless success

                c[:data] = ''

                c.on_eof do
                  begin
                  rsock.close
                rescue
                  nil
                end
                  begin
                    self.ssh.close
                  rescue
                    nil
                  end
                  thread.kill
                end

                c.on_close do
                  begin
                  rsock.close
                rescue
                  nil
                end
                  begin
                    self.ssh.close
                  rescue
                    nil
                  end
                  thread.kill
                end

                c.on_data do |_ch, data|
                  rsock.write(data)
                end

                c.on_extended_data do |_ch, _ctype, data|
                  rsock.write(data)
                end

                self.channel = c
              end
            end

            self.monitor = Thread.new do
              loop do
                next unless rsock.has_read_data?(1.0)
                buff = rsock.read(16384)
                break unless buff
                verify_channel
                channel.send_data(buff) if buff
              end
            end

            loop do
              rssh.process(0.5) { true }
            end

          rescue ::Exception => e
            self.error = e
            #::Kernel.warn "BOO: #{e.inspect}"
            #::Kernel.warn e.backtrace.join("\n")
          ensure
            monitor&.kill
          end

          # Shut down the SSH session if requested
          rssh.close if rcleanup
        end
      end

      #
      # Prevent a race condition
      #
      def verify_channel
        until channel
          raise EOFError unless thread.alive?
          ::IO.select(nil, nil, nil, 0.10)
        end
      end
    end
  end
end
