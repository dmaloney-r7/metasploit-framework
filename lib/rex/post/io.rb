# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Post
    ##
    #
    # Base IO class that is modeled after the ruby IO class.
    #
    ##
    class IO
      protected

        attr_accessor :filed, :mode

      public

        ##
        #
        # Conditionals
        #
        ##

        def eof?
          eof
        end

        def closed?
          raise NotImplementedError
        end

        def tty?
          isatty
        end

        ##
        #
        # I/O operations
        #
        ##

        def binmode
          raise NotImplementedError
        end

        def close
          raise NotImplementedError
        end

        def close_read
          raise NotImplementedError
        end

        def close_write
          raise NotImplementedError
        end

        def each(_sep = $INPUT_RECORD_SEPARATOR)
          raise NotImplementedError
        end

        def each_line(_sep = $INPUT_RECORD_SEPARATOR)
          raise NotImplementedError
        end

        def each_byte
          raise NotImplementedError
        end

        def eof
          raise NotImplementedError
        end

        def fcntl(_cmd, _arg)
          raise NotImplementedError
        end

        def flush
          raise NotImplementedError
        end

        def fsync
          raise NotImplementedError
        end

        def getc
          raise NotImplementedError
        end

        def gets(_sep = $INPUT_RECORD_SEPARATOR)
          raise NotImplementedError
        end

        def ioctl(_cmd, _arg)
          raise NotImplementedError
        end

        def isatty
          raise NotImplementedError
        end

        def lineno
          raise NotImplementedError
        end

        def pos
          raise NotImplementedError
        end

        def print
          raise NotImplementedError
        end

        def printf(_fmt, *_args)
          raise NotImplementedError
        end

        def putc(_obj)
          raise NotImplementedError
        end

        def puts(_obj)
          raise NotImplementedError
        end

        def read(_length = nil, _buffer = nil)
          raise NotImplementedError
        end

        def readchar
          raise NotImplementedError
        end

        def readline(_sep = $INPUT_RECORD_SEPARATOR)
          raise NotImplementedError
        end

        def readlines(_sep = $INPUT_RECORD_SEPARATOR)
          raise NotImplementedError
        end

        def rewind
          raise NotImplementedError
        end

        def seek(_offset, _whence = SEEK_SET)
          raise NotImplementedError
        end

        def stat
          raise NotImplementedError
        end

        def sync
          raise NotImplementedError
        end

        def sysread(_length)
          raise NotImplementedError
        end

        def sysseek(_offset, _whence = SEEK_SET)
          raise NotImplementedError
        end

        def syswrite(_buf)
          raise NotImplementedError
        end

        def tell
          pos
        end

        def ungetc(_val)
          raise NotImplementedError
        end

        def write(_buf)
          raise NotImplementedError
        end
    end
  end; end # Post/Rex
