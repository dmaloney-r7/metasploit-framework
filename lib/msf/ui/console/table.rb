# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  module Ui
    module Console
      ###
      #
      # Console table display wrapper that allows for stylized tables
      #
      ###
      class Table < Rex::Text::Table
        #
        # Default table styles.
        #
        module Style
          Default = 0
        end

        #
        # Initializes a wrappered table with the supplied style and options.
        #
        def initialize(style, opts = {})
          self.style = style

          if self.style == Style::Default
            opts['Indent'] = 3
            opts['Prefix']  = "\n" unless opts['Prefix']
            opts['Postfix'] = "\n" unless opts['Postfix']

            super(opts)
          end
        end

        #
        # Print nothing if there are no rows if the style is default.
        #
        def to_s
          if style == Style::Default
            return '' if rows.empty?
          end

          super
        end

        protected

        attr_accessor :style # :nodoc:
      end
    end
  end
end
