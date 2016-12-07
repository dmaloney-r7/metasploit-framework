# frozen_string_literal: true
# -*- coding: binary -*-
require 'msf/core'

###
#
# This class provides basic XOR encoding of buffers.
#
###
class Msf::Encoder::Xor < Msf::Encoder
  #
  # Encodes a block using the XOR encoder from the Rex library.
  #
  def encode_block(state, block)
    encoder = case state.decoder_key_size
              when Rex::Encoding::Xor::Qword.keysize then Rex::Encoding::Xor::Qword
              when Rex::Encoding::Xor::Dword.keysize then	Rex::Encoding::Xor::Dword
              when Rex::Encoding::Xor::Word.keysize then Rex::Encoding::Xor::Word
              when Rex::Encoding::Xor::Byte.keysize then Rex::Encoding::Xor::Byte
              else Rex::Encoding::Xor::Dword
    end
    encoder.encode(block, [ state.key ].pack(state.decoder_key_pack))[0]
  end

  #
  # Finds keys that are incompatible with the supplied bad character list.
  #
  def find_bad_keys(buf, badchars)
    # Short circuit if there are no badchars
    return super if badchars.empty?

    bad_keys = Array.new(decoder_key_size) { Hash.new }
    byte_idx = 0

    # Scan through all the badchars and build out the bad_keys array
    # based on the XOR'd combinations that can occur at certain bytes
    # to produce bad characters
    buf.each_byte do |byte|
      badchars.each_byte do |badchar|
        bad_keys[byte_idx % decoder_key_size][byte ^ badchar] = true
      end
      byte_idx += 1
    end

    badchars.each_byte do |badchar|
      0.upto(decoder_key_size - 1) do |i|
        bad_keys[i][badchar] = true
      end
    end

    bad_keys
  end
end
