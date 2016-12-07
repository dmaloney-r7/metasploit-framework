# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui'

module Rex
  module Ui
    module Text
      ###
      #
      # This class implements output against a file
      #
      ###
      class Output::File < Rex::Ui::Text::Output
        attr_accessor :fd

        def initialize(path, mode = 'wb')
          self.fd = ::File.open(path, mode)
        end

        def supports_color?
          false
        end

        #
        # Prints the supplied message to file output.
        #
        def print_raw(msg = '')
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
