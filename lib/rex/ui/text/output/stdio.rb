# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui'

begin
  require 'windows_console_color_support'
rescue ::LoadError
end

module Rex
  module Ui
    module Text
      ###
      #
      # This class implements output against standard out.
      #
      ###
      class Output::Stdio < Rex::Ui::Text::Output
        #
        # Attributes
        #

        # @!attribute io
        #   The raw `IO` backing this Text output.  Defaults to `$stdout`
        #
        #   @return [#flush, #puts, #write]
        attr_writer :io

        #
        # Constructor
        #

        # @param options [Hash{Symbol => IO}]
        # @option options [IO]
        def initialize(options = {})
          options.assert_valid_keys(:io)

          super()

          self.io = options[:io]
        end

        #
        # Methods
        #

        def flush
          io.flush
        end

        # IO to write to.
        #
        # @return [IO] Default to `$stdout`
        def io
          @io ||= $stdout
        end

        # Use ANSI Control chars to reset prompt position for async output
        # SEE https://github.com/rapid7/metasploit-framework/pull/7570
        def print_line(msg = '')
          if /mingw/ =~ RUBY_PLATFORM
            print(msg + "\n")
            return
          end
          print("\033[s") # Save cursor position
          print("\r\033[K" + msg + "\n")
          if input && input.prompt
            print("\r\033[K")
            print(input.prompt.tr("\001\002", ''))
            print(input.line_buffer.tr("\001\002", ''))
            print("\033[u\033[B") # Restore cursor, move down one line
          end
        end

        #
        # Prints the supplied message to standard output.
        #
        def print_raw(msg = '')
          if Rex::Compat.is_windows && supports_color?
            WindowsConsoleColorSupport.new(io).write(msg)
          else
            io.print(msg)
          end

          io.flush

          msg
        end
        alias write print_raw

        def supports_color?
          case config[:color]
          when true
            true
          when false
            false
          else # auto
            return true if Rex::Compat.is_windows
            term = Rex::Compat.getenv('TERM')
            (term && !term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i).nil?)
          end
        end
      end
    end
  end
end
