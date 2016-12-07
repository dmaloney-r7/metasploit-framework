# frozen_string_literal: true
# -*- coding: binary -*-
require "rex/text"

module Rex
  module Proto
    module DCERPC
      class NDR
        # Provide padding to align the string to the 32bit boundary
        def self.align(string)
          warn 'should be using Rex::Encoder::NDR'
          "\x00" * ((4 - (string.length & 3)) & 3)
        end

        # Encode a 4 byte long
        # use to encode:
        #       long element_1;
        def self.long(string)
          warn 'should be using Rex::Encoder::NDR'
          [string].pack('V')
        end

        # Encode a 2 byte short
        # use to encode:
        #       short element_1;
        def self.short(string)
          warn 'should be using Rex::Encoder::NDR'
          [string].pack('v')
        end

        # Encode a single byte
        # use to encode:
        #       byte element_1;
        def self.byte(string)
          warn 'should be using Rex::Encoder::NDR'
          [string].pack('C')
        end

        # Encode a byte array
        # use to encode:
        #       char  element_1
        def self.UniConformantArray(string)
          warn 'should be using Rex::Encoder::NDR'
          long(string.length) + string + align(string)
        end

        # Encode a string
        # use to encode:
        #       w_char *element_1;
        def self.UnicodeConformantVaryingString(string)
          warn 'should be using Rex::Encoder::NDR'
          string += "\x00" # null pad
          long(string.length) + long(0) + long(string.length) + Rex::Text.to_unicode(string) + align(Rex::Text.to_unicode(string))
        end

        # Encode a string that is already unicode encoded
        # use to encode:
        #       w_char *element_1;
        def self.UnicodeConformantVaryingStringPreBuilt(string)
          warn 'should be using Rex::Encoder::NDR'
          # if the string len is odd, thats bad!
          string += "\x00" if string.length % 2 > 0
          len = string.length / 2
          long(len) + long(0) + long(len) + string + align(string)
        end
      end
    end
  end
end
