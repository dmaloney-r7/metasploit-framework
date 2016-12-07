# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        class Element
          include Rex::Proto::Kerberos::Crypto
          include Rex::Proto::Kerberos::Pac

          def self.attr_accessor(*vars)
            @attributes ||= []
            @attributes.concat vars
            super(*vars)
          end

          # Retrieves the element class fields
          #
          # @return [Array]
          class << self
            attr_reader :attributes
          end

          def initialize(options = {})
            self.class.attributes.each do |attr|
              if options.key?(attr)
                m = (attr.to_s + '=').to_sym
                send(m, options[attr])
              end
            end
          end

          # Retrieves the element instance fields
          #
          # @return [Array]
          def attributes
            self.class.attributes
          end

          # Encodes the Rex::Proto::Kerberos::Pac::Element into an String. This
          # method has been designed to be overridden by subclasses.
          #
          # @raise [NoMethodError]
          def encode
            raise ::NoMethodError, 'Method designed to be overridden'
          end
        end
      end
    end
  end
end
