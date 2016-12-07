# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui'

module Rex
  module Ui
    module Text
      ###
      #
      # This class implements output against a file and stdout
      #
      ###
      class Output::Tee < Rex::Ui::Text::Output
        attr_accessor :fd

        def initialize(path)
          self.fd = ::File.open(path, "ab")
          super()
        end

        def supports_color?
          case config[:color]
          when true
            true
          when false
            false
          else # auto
            term = Rex::Compat.getenv('TERM')
            (term && !term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i).nil?)
          end
        end

        #
        # Prints the supplied message to file output.
        #
        def print_raw(msg = '')
          $stdout.print(msg)
          $stdout.flush

          return unless fd
          fd.write(msg)
          fd.flush
          msg
        end

        alias write print_raw

        def close
          fd&.close
          self.fd = nil
        end
      end
      end
  end
end
