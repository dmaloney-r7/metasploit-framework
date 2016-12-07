# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Proto
    module SMB
      class SimpleClient
        class OpenFile
          attr_accessor	:name, :tree_id, :file_id, :mode, :client, :chunk_size

          def initialize(client, name, tree_id, file_id)
            self.client = client
            self.name = name
            self.tree_id = tree_id
            self.file_id = file_id
            self.chunk_size = 48000
          end

          def delete
            begin
              close
            rescue
            end
            client.delete(name, tree_id)
          end

          # Close this open file
          def close
            client.close(file_id, tree_id)
          end

          # Read data from the file
          def read(length = nil, offset = 0)
            if length.nil?
              data = ''
              fptr = offset
              ok = client.read(file_id, fptr, chunk_size)
              while ok && ok['Payload'].v['DataLenLow'] > 0
                buff = ok.to_s.slice(
                  ok['Payload'].v['DataOffset'] + 4,
                  ok['Payload'].v['DataLenLow']
                )
                data << buff
                break if ok['Payload'].v['Remaining'] == 0
                fptr += ok['Payload'].v['DataLenLow']

                begin
                  ok = client.read(file_id, fptr, chunk_size)
                rescue XCEPT::ErrorCode => e
                  case e.error_code
                  when 0x00050001
                    # Novell fires off an access denied error on EOF
                    ok = nil
                  else
                    raise e
                  end
                end
              end

              data
            else
              ok = client.read(file_id, offset, length)
              data = ok.to_s.slice(
                ok['Payload'].v['DataOffset'] + 4,
                ok['Payload'].v['DataLenLow']
              )
              data
            end
          end

          def <<(data)
            write(data)
          end

          # Write data to the file
          def write(data, offset = 0)
            # Track our offset into the remote file
            fptr = offset

            # Duplicate the data so we can use slice!
            data = data.dup

            # Take our first chunk of bytes
            chunk = data.slice!(0, chunk_size)

            # Keep writing data until we run out
            until chunk.empty?
              ok = client.write(file_id, fptr, chunk)
              cl = ok['Payload'].v['CountLow']

              # Partial write, push the failed data back into the queue
              data = chunk.slice(cl - 1, chunk.length - cl) + data if cl != chunk.length

              # Increment our painter and grab the next chunk
              fptr += cl
              chunk = data.slice!(0, chunk_size)
            end
          end
        end
      end
    end
  end
end
