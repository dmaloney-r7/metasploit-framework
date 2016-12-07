# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui'

module Rex
  module Ui
    module Text
      require 'rex/io/stream_abstraction'

      ###
      #
      # This class implements input against a socket.
      #
      ###
      class Input::Buffer < Rex::Ui::Text::Input
        class BufferSock
          include Rex::IO::StreamAbstraction
          def write(buf, _opts = {})
            syswrite(buf)
          end
      end

        def initialize
          @sock = BufferSock.new
          @sock.initialize_abstraction
        end

        def close
          @sock.cleanup_abstraction
        end

        def sysread(len = 1)
          @sock.rsock.sysread(len)
        end

        def put(msg, _opts = {})
          @sock.lsock.write(msg)
        end

        #
        # Wait for a line of input to be read from a socket.
        #
        def gets
          # Initialize the line buffer
          line = ''

          # Read data one byte at a time until we see a LF
          loop do
            break if line.include?("\n")

            # Read another character of input
            char = @sock.rsock.getc

            # Append this character to the string
            line << char
          end

          line
        end

        #
        # Returns whether or not EOF has been reached on stdin.
        #
        def eof?
          @sock.lsock.closed?
        end

        #
        # Returns the file descriptor associated with a socket.
        #
        def fd
          @sock.rsock
        end
      end
      end
  end
end
