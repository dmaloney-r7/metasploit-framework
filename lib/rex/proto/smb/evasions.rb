# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Proto
    module SMB
      class Evasions
        require 'rex/text'

        EVASION_NONE  = 0
        EVASION_LOW   = 1
        EVASION_HIGH  = 2
        EVASION_MAX   = 3

        # Add bogus filler at the end of the SMB packet and before the data
        def self.make_offset_filler(level, max_size = 60000, min_size = 512)
          max_size = 4096 if max_size < 0

          min_size = max_size - 1 if min_size < max_size

          case level.to_i
          when EVASION_LOW
            Rex::Text.rand_text(32)
          when EVASION_HIGH
            Rex::Text.rand_text(rand(max_size - min_size) + min_size)
          when EVASION_MAX
            Rex::Text.rand_text(rand(max_size))
          else EVASION_NONE
               return ''
          end
        end

        # Obscures a named pipe pathname via leading and trailing slashes
        def self.make_named_pipe_path(level, pipe)
          case level.to_i
          when EVASION_LOW
            ('\\' * (1024 + rand(512))) + pipe
          when EVASION_HIGH, EVASION_MAX
            return ('\\' * (1024 + rand(512))) + pipe + ('\\' * (1024 + rand(512)))
          else
            '\\' + pipe
          end
        end

        # Obscures the TransactNamedPipe \PIPE\ string
        def self.make_trans_named_pipe_name(level)
          case level.to_i
          when EVASION_LOW
            ('\\' * (256 - rand(64)) + 'PIPE\\')
          when EVASION_HIGH
            Rex::Text.rand_text(512 - rand(128))
          when EVASION_MAX
            Rex::Text.rand_text(1024 - rand(256))
          else
            '\\PIPE\\'
          end
        end
      end
    end
  end
end
