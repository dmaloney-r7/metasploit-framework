# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Proto
    module SMB
      class SimpleClient
        class OpenPipe < OpenFile
          # Valid modes are: 'trans' and 'rw'
          attr_accessor :mode

          def initialize(*args)
            super(*args)
            self.mode = 'rw'
            @buff = ''
          end

          def read_buffer(length, _offset = 0)
            length ||= @buff.length
            @buff.slice!(0, length)
          end

          def read(length = nil, offset = 0)
            case mode
            when 'trans'
              read_buffer(length, offset)
            when 'rw'
              super(length, offset)
            else
              raise ArgumentError
            end
          end

          def write(data, offset = 0)
            case mode

            when 'trans'
              write_trans(data, offset)
            when 'rw'
              super(data, offset)
            else
              raise ArgumentError
            end
          end

          def write_trans(data, _offset = 0)
            ack = client.trans_named_pipe(file_id, data)
            doff = ack['Payload'].v['DataOffset']
            dlen = ack['Payload'].v['DataCount']
            @buff << ack.to_s[4 + doff, dlen]
          end
      end
      end
    end
  end
end
