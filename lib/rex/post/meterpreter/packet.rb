# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      #
      # Constants
      #
      PACKET_TYPE_REQUEST = 0
      PACKET_TYPE_RESPONSE        = 1
      PACKET_TYPE_PLAIN_REQUEST   = 10
      PACKET_TYPE_PLAIN_RESPONSE  = 11

      #
      # TLV Meta Types
      #
      TLV_META_TYPE_NONE          = 0
      TLV_META_TYPE_STRING        = (1 << 16)
      TLV_META_TYPE_UINT          = (1 << 17)
      TLV_META_TYPE_RAW           = (1 << 18)
      TLV_META_TYPE_BOOL          = (1 << 19)
      TLV_META_TYPE_QWORD         = (1 << 20)
      TLV_META_TYPE_COMPRESSED    = (1 << 29)
      TLV_META_TYPE_GROUP         = (1 << 30)
      TLV_META_TYPE_COMPLEX       = (1 << 31)

      # Exclude compressed from the mask since other meta types (e.g. RAW) can also
      # be compressed
      TLV_META_MASK = (
        TLV_META_TYPE_STRING |
        TLV_META_TYPE_UINT |
        TLV_META_TYPE_RAW |
        TLV_META_TYPE_BOOL |
        TLV_META_TYPE_QWORD |
        TLV_META_TYPE_GROUP |
        TLV_META_TYPE_COMPLEX
      )

      #
      # TLV base starting points
      #
      TLV_RESERVED                = 0
      TLV_EXTENSIONS              = 20000
      TLV_USER                    = 40000
      TLV_TEMP                    = 60000

      #
      # TLV Specific Types
      #
      TLV_TYPE_ANY                 = TLV_META_TYPE_NONE   |   0
      TLV_TYPE_METHOD              = TLV_META_TYPE_STRING |   1
      TLV_TYPE_REQUEST_ID          = TLV_META_TYPE_STRING |   2
      TLV_TYPE_EXCEPTION           = TLV_META_TYPE_GROUP  |   3
      TLV_TYPE_RESULT              = TLV_META_TYPE_UINT   |   4

      TLV_TYPE_STRING              = TLV_META_TYPE_STRING |  10
      TLV_TYPE_UINT                = TLV_META_TYPE_UINT   |  11
      TLV_TYPE_BOOL                = TLV_META_TYPE_BOOL   |  12

      TLV_TYPE_LENGTH              = TLV_META_TYPE_UINT   |  25
      TLV_TYPE_DATA                = TLV_META_TYPE_RAW    |  26
      TLV_TYPE_FLAGS               = TLV_META_TYPE_UINT   |  27

      TLV_TYPE_CHANNEL_ID          = TLV_META_TYPE_UINT   |  50
      TLV_TYPE_CHANNEL_TYPE        = TLV_META_TYPE_STRING |  51
      TLV_TYPE_CHANNEL_DATA        = TLV_META_TYPE_RAW    |  52
      TLV_TYPE_CHANNEL_DATA_GROUP  = TLV_META_TYPE_GROUP  |  53
      TLV_TYPE_CHANNEL_CLASS       = TLV_META_TYPE_UINT   |  54
      TLV_TYPE_CHANNEL_PARENTID    = TLV_META_TYPE_UINT   |  55

      TLV_TYPE_SEEK_WHENCE         = TLV_META_TYPE_UINT   |  70
      TLV_TYPE_SEEK_OFFSET         = TLV_META_TYPE_UINT   |  71
      TLV_TYPE_SEEK_POS            = TLV_META_TYPE_UINT   |  72

      TLV_TYPE_EXCEPTION_CODE      = TLV_META_TYPE_UINT   | 300
      TLV_TYPE_EXCEPTION_STRING    = TLV_META_TYPE_STRING | 301

      TLV_TYPE_LIBRARY_PATH        = TLV_META_TYPE_STRING | 400
      TLV_TYPE_TARGET_PATH         = TLV_META_TYPE_STRING | 401
      TLV_TYPE_MIGRATE_PID         = TLV_META_TYPE_UINT   | 402
      TLV_TYPE_MIGRATE_LEN         = TLV_META_TYPE_UINT   | 403
      TLV_TYPE_MIGRATE_PAYLOAD     = TLV_META_TYPE_STRING | 404
      TLV_TYPE_MIGRATE_ARCH        = TLV_META_TYPE_UINT   | 405
      TLV_TYPE_MIGRATE_BASE_ADDR   = TLV_META_TYPE_UINT   | 407
      TLV_TYPE_MIGRATE_ENTRY_POINT = TLV_META_TYPE_UINT   | 408
      TLV_TYPE_MIGRATE_SOCKET_PATH = TLV_META_TYPE_STRING | 409

      TLV_TYPE_TRANS_TYPE          = TLV_META_TYPE_UINT   | 430
      TLV_TYPE_TRANS_URL           = TLV_META_TYPE_STRING | 431
      TLV_TYPE_TRANS_UA            = TLV_META_TYPE_STRING | 432
      TLV_TYPE_TRANS_COMM_TIMEOUT  = TLV_META_TYPE_UINT   | 433
      TLV_TYPE_TRANS_SESSION_EXP   = TLV_META_TYPE_UINT   | 434
      TLV_TYPE_TRANS_CERT_HASH     = TLV_META_TYPE_RAW    | 435
      TLV_TYPE_TRANS_PROXY_HOST    = TLV_META_TYPE_STRING | 436
      TLV_TYPE_TRANS_PROXY_USER    = TLV_META_TYPE_STRING | 437
      TLV_TYPE_TRANS_PROXY_PASS    = TLV_META_TYPE_STRING | 438
      TLV_TYPE_TRANS_RETRY_TOTAL   = TLV_META_TYPE_UINT   | 439
      TLV_TYPE_TRANS_RETRY_WAIT    = TLV_META_TYPE_UINT   | 440
      TLV_TYPE_TRANS_GROUP         = TLV_META_TYPE_GROUP  | 441

      TLV_TYPE_MACHINE_ID          = TLV_META_TYPE_STRING | 460
      TLV_TYPE_UUID                = TLV_META_TYPE_RAW    | 461

      TLV_TYPE_CIPHER_NAME         = TLV_META_TYPE_STRING | 500
      TLV_TYPE_CIPHER_PARAMETERS   = TLV_META_TYPE_GROUP  | 501

      #
      # Core flags
      #
      LOAD_LIBRARY_FLAG_ON_DISK   = (1 << 0)
      LOAD_LIBRARY_FLAG_EXTENSION = (1 << 1)
      LOAD_LIBRARY_FLAG_LOCAL     = (1 << 2)

      ###
      #
      # Base TLV (Type-Length-Value) class
      #
      ###
      class Tlv
        attr_accessor :type, :value, :compress

        ##
        #
        # Constructor
        #
        ##

        #
        # Returns an instance of a TLV.
        #
        def initialize(type, value = nil, compress = false)
          @type     = type
          @compress = compress

          unless value.nil?
            @value = if type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING
                       if value.is_a?(Integer)
                         value.to_s
                       else
                         value.dup
                                end
                     else
                       value
                     end
          end
        end

        def inspect
          utype = type ^ TLV_META_TYPE_COMPRESSED
          group = false
          meta = case (utype & TLV_META_MASK)
                 when TLV_META_TYPE_STRING then "STRING"
                 when TLV_META_TYPE_UINT then "INT"
                 when TLV_META_TYPE_RAW then "RAW"
                 when TLV_META_TYPE_BOOL then "BOOL"
                 when TLV_META_TYPE_QWORD then "QWORD"
                 when TLV_META_TYPE_GROUP then group = true; "GROUP"
                 when TLV_META_TYPE_COMPLEX then "COMPLEX"
                 else; 'unknown-meta-type'
            end
          stype = case type
                  when PACKET_TYPE_REQUEST then "Request"
                  when PACKET_TYPE_RESPONSE then "Response"
                  when TLV_TYPE_REQUEST_ID then "REQUEST-ID"
                  when TLV_TYPE_METHOD then "METHOD"
                  when TLV_TYPE_RESULT then "RESULT"
                  when TLV_TYPE_EXCEPTION then "EXCEPTION"
                  when TLV_TYPE_STRING then "STRING"
                  when TLV_TYPE_UINT then "UINT"
                  when TLV_TYPE_BOOL then "BOOL"

                  when TLV_TYPE_LENGTH then "LENGTH"
                  when TLV_TYPE_DATA then "DATA"
                  when TLV_TYPE_FLAGS then "FLAGS"

                  when TLV_TYPE_CHANNEL_ID then "CHANNEL-ID"
                  when TLV_TYPE_CHANNEL_TYPE then "CHANNEL-TYPE"
                  when TLV_TYPE_CHANNEL_DATA then "CHANNEL-DATA"
                  when TLV_TYPE_CHANNEL_DATA_GROUP then "CHANNEL-DATA-GROUP"
                  when TLV_TYPE_CHANNEL_CLASS then "CHANNEL-CLASS"
                  when TLV_TYPE_CHANNEL_PARENTID then "CHANNEL-PARENTID"

                  when TLV_TYPE_SEEK_WHENCE then "SEEK-WHENCE"
                  when TLV_TYPE_SEEK_OFFSET then "SEEK-OFFSET"
                  when TLV_TYPE_SEEK_POS then "SEEK-POS"

                  when TLV_TYPE_EXCEPTION_CODE then "EXCEPTION-CODE"
                  when TLV_TYPE_EXCEPTION_STRING then "EXCEPTION-STRING"

                  when TLV_TYPE_LIBRARY_PATH then "LIBRARY-PATH"
                  when TLV_TYPE_TARGET_PATH then "TARGET-PATH"
                  when TLV_TYPE_MIGRATE_PID then "MIGRATE-PID"
                  when TLV_TYPE_MIGRATE_LEN then "MIGRATE-LEN"
                  when TLV_TYPE_MIGRATE_PAYLOAD then "MIGRATE-PAYLOAD"
                  when TLV_TYPE_MIGRATE_ARCH then "MIGRATE-ARCH"
                  when TLV_TYPE_TRANS_TYPE then "TRANS-TYPE"
                  when TLV_TYPE_TRANS_URL then "TRANS-URL"
                  when TLV_TYPE_TRANS_COMM_TIMEOUT then "TRANS-COMM-TIMEOUT"
                  when TLV_TYPE_TRANS_SESSION_EXP then "TRANS-SESSION-EXP"
                  when TLV_TYPE_TRANS_CERT_HASH then "TRANS-CERT-HASH"
                  when TLV_TYPE_TRANS_PROXY_HOST then "TRANS-PROXY-HOST"
                  when TLV_TYPE_TRANS_PROXY_USER then "TRANS-PROXY-USER"
                  when TLV_TYPE_TRANS_PROXY_PASS then "TRANS-PROXY-PASS"
                  when TLV_TYPE_TRANS_RETRY_TOTAL then "TRANS-RETRY-TOTAL"
                  when TLV_TYPE_TRANS_RETRY_WAIT then "TRANS-RETRY-WAIT"
                  when TLV_TYPE_MACHINE_ID then "MACHINE-ID"
                  when TLV_TYPE_UUID then "UUID"

                  # when Extensions::Stdapi::TLV_TYPE_NETWORK_INTERFACE; 'network-interface'
                  # when Extensions::Stdapi::TLV_TYPE_IP; 'ip-address'
                  # when Extensions::Stdapi::TLV_TYPE_NETMASK; 'netmask'
                  # when Extensions::Stdapi::TLV_TYPE_MAC_ADDRESS; 'mac-address'
                  # when Extensions::Stdapi::TLV_TYPE_MAC_NAME; 'interface-name'
                  # when Extensions::Stdapi::TLV_TYPE_IP6_SCOPE; 'address-scope'
                  # when Extensions::Stdapi::TLV_TYPE_INTERFACE_MTU; 'interface-mtu'
                  # when Extensions::Stdapi::TLV_TYPE_INTERFACE_FLAGS; 'interface-flags'
                  # when Extensions::Stdapi::TLV_TYPE_INTERFACE_INDEX; 'interface-index'

                  else; "unknown-#{type}"
            end
          val = value.inspect
          val = val[0, 50] + ' ..."' if val.length > 50
          group ||= (self.class.to_s =~ /Packet/)
          if group
            tlvs_inspect = "tlvs=[\n"
            @tlvs.each do |t|
              tlvs_inspect << "  #{t.inspect}\n"
            end
            tlvs_inspect << "]"
          else
            tlvs_inspect = "meta=#{meta.ljust 10} value=#{val}"
          end
          "#<#{self.class} type=#{stype.ljust 15} #{tlvs_inspect}>"
        end

        ##
        #
        # Conditionals
        #
        ##

        #
        # Checks to see if a TLVs meta type is equivalent to the meta type passed.
        #
        def meta_type?(meta)
          (type & meta == meta)
        end

        #
        # Checks to see if the TLVs type is equivalent to the type passed.
        #
        def type?(type)
          self.type == type
        end

        #
        # Checks to see if the TLVs value is equivalent to the value passed.
        #
        def value?(value)
          self.value == value
        end

        ##
        #
        # Serializers
        #
        ##

        #
        # Converts the TLV to raw.
        #
        def to_r
          # Forcibly convert to ASCII-8BIT encoding
          raw = value.to_s.unpack("C*").pack("C*")

          if type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING
            raw += "\x00"
          elsif type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT
            raw = [value].pack("N")
          elsif type & TLV_META_TYPE_QWORD == TLV_META_TYPE_QWORD
            raw = [ htonq(value.to_i) ].pack("Q<")
          elsif type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL
            raw = if value == true
                    [1].pack("c")
                  else
                    [0].pack("c")
                  end
          end

          # check if the tlv is to be compressed...
          if @compress
            raw_uncompressed = raw
            # compress the raw data
            raw_compressed = Rex::Text.zlib_deflate(raw_uncompressed)
            # check we have actually made the raw data smaller...
            # (small blobs often compress slightly larger then the origional)
            # if the compressed data is not smaller, we dont use the compressed data
            if raw_compressed.length < raw_uncompressed.length
              # if so, set the TLV's type to indicate compression is used
              self.type = type | TLV_META_TYPE_COMPRESSED
              # update the raw data with the uncompressed data length + compressed data
              # (we include the uncompressed data length as the C side will need to know this for decompression)
              raw = [ raw_uncompressed.length ].pack("N") + raw_compressed
            end
          end

          [raw.length + 8, type].pack("NN") + raw
        end

        #
        # Translates the raw format of the TLV into a sanitize version.
        #
        def from_r(raw)
          self.value = nil

          length, self.type = raw.unpack("NN")

          # check if the tlv value has been compressed...
          if type & TLV_META_TYPE_COMPRESSED == TLV_META_TYPE_COMPRESSED
            # set this TLV as using compression
            @compress = true
            # remove the TLV_META_TYPE_COMPRESSED flag from the tlv type to restore the
            # tlv type to its origional, allowing for transparent data compression.
            self.type = type ^ TLV_META_TYPE_COMPRESSED
            # decompress the compressed data (skipping the length and type DWORD's)
            raw_decompressed = Rex::Text.zlib_inflate(raw[8..length - 1])
            # update the length to reflect the decompressed data length (+8 for the length and type DWORD's)
            length = raw_decompressed.length + 8
            # update the raw buffer with the new length, decompressed data and updated type.
            raw = [length, type].pack("NN") + raw_decompressed
          end

          if type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING
            self.value = (raw[8..length - 2] unless raw.empty?)
          elsif type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT
            self.value = raw.unpack("NNN")[2]
          elsif type & TLV_META_TYPE_QWORD == TLV_META_TYPE_QWORD
            self.value = raw.unpack("NNQ<")[2]
            self.value = ntohq(value)
          elsif type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL
            self.value = raw.unpack("NNc")[2]

            self.value = if value == 1
                           true
                         else
                           false
                         end
          else
            self.value = raw[8..length - 1]
          end

          length
        end

        protected

        def htonq(value)
          return value if [1].pack('s') == [1].pack('n')
          [ value ].pack('Q<').reverse.unpack('Q<').first
        end

        def ntohq(value)
          htonq(value)
        end
      end

      ###
      #
      # Group TLVs contain zero or more TLVs
      #
      ###
      class GroupTlv < Tlv
        attr_accessor :tlvs

        ##
        #
        # Constructor
        #
        ##

        #
        # Initializes the group TLV container to the supplied type
        # and creates an empty TLV array.
        #
        def initialize(type)
          super(type)

          self.tlvs = [ ]
        end

        ##
        #
        # Group-based TLV accessors
        #
        ##

        #
        # Enumerates TLVs of the supplied type.
        #
        def each(type = TLV_TYPE_ANY, &block)
          get_tlvs(type).each(&block)
        end

        #
        # Synonym for each.
        #
        def each_tlv(type = TLV_TYPE_ANY, &block)
          each(type, &block)
        end

        #
        # Enumerates TLVs of a supplied type with indexes.
        #
        def each_with_index(type = TLV_TYPE_ANY, &block)
          get_tlvs(type).each_with_index(&block)
        end

        #
        # Synonym for each_with_index.
        #
        def each_tlv_with_index(type = TLV_TYPE_ANY, &block)
          each_with_index(type, block)
        end

        #
        # Returns an array of TLVs for the given type.
        #
        def get_tlvs(type)
          if type == TLV_TYPE_ANY
            tlvs
          else
            type_tlvs = []

            tlvs.each do |tlv|
              type_tlvs << tlv if tlv.type?(type)
            end

            type_tlvs
          end
        end

        ##
        #
        # TLV management
        #
        ##

        #
        # Adds a TLV of a given type and value.
        #
        def add_tlv(type, value = nil, replace = false, compress = false)
          # If we should replace any TLVs with the same type...remove them first
          if replace
            each(type) do |tlv|
              tlvs.delete(tlv) if tlv.type == type
            end
          end

          tlv = if type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP
                  GroupTlv.new(type)
                else
                  Tlv.new(type, value, compress)
                end

          tlvs << tlv

          tlv
        end

        #
        # Adds zero or more TLVs to the packet.
        #
        def add_tlvs(tlvs)
          tlvs&.each do |tlv|
            add_tlv(tlv['type'], tlv['value'])
          end
        end

        #
        # Gets the first TLV of a given type.
        #
        def get_tlv(type, index = 0)
          type_tlvs = get_tlvs(type)

          return type_tlvs[index] if type_tlvs.length > index

          nil
        end

        #
        # Returns the value of a TLV if it exists, otherwise nil.
        #
        def get_tlv_value(type, index = 0)
          tlv = get_tlv(type, index)

          !tlv.nil? ? tlv.value : nil
        end

        #
        # Returns an array of values for all tlvs of type type.
        #
        def get_tlv_values(type)
          get_tlvs(type).collect(&:value)
        end

        #
        # Checks to see if the container has a TLV of a given type.
        #
        def has_tlv?(type)
          !get_tlv(type).nil?
        end

        #
        # Zeros out the array of TLVs.
        #
        def reset
          self.tlvs = []
        end

        ##
        #
        # Serializers
        #
        ##

        #
        # Converts all of the TLVs in the TLV array to raw and prefixes them
        # with a container TLV of this instance's TLV type.
        #
        def to_r
          raw = ''

          each do |tlv|
            raw << tlv.to_r
          end

          [raw.length + 8, type].pack("NN") + raw
        end

        #
        # Converts the TLV group container from raw to all of the individual
        # TLVs.
        #
        def from_r(raw)
          offset = 8

          # Reset the TLVs array
          self.tlvs = []
          self.type = raw.unpack("NN")[1]

          # Enumerate all of the TLVs
          while offset < raw.length - 1

            tlv = nil

            # Get the length and type
            length, type = raw[offset..offset + 8].unpack("NN")

            tlv = if type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP
                    GroupTlv.new(type)
                  else
                    Tlv.new(type)
                  end

            tlv.from_r(raw[offset..offset + length])

            # Insert it into the list of TLVs
            tlvs << tlv

            # Move up
            offset += length
          end
        end
      end

      ###
      #
      # The logical meterpreter packet class
      #
      ###
      class Packet < GroupTlv
        attr_accessor :created_at

        ##
        #
        # Factory
        #
        ##

        #
        # Creates a request with the supplied method.
        #
        def self.create_request(method = nil)
          Packet.new(PACKET_TYPE_REQUEST, method)
        end

        #
        # Creates a response to a request if one is provided.
        #
        def self.create_response(request = nil)
          response_type = PACKET_TYPE_RESPONSE
          method = nil

          if request
            if request.type?(PACKET_TYPE_PLAIN_REQUEST)
              response_type = PACKET_TYPE_PLAIN_RESPONSE
            end

            method = request.method
          end

          Packet.new(response_type, method)
        end

        ##
        #
        # Constructor
        #
        ##

        #
        # Initializes the packet to the supplied packet type and method,
        # if any.  If the packet is a request, a request identifier is
        # created.
        #
        def initialize(type = nil, method = nil)
          super(type)

          self.method = method if method

          self.created_at = ::Time.now

          # If it's a request, generate a random request identifier
          if (type == PACKET_TYPE_REQUEST) ||
             (type == PACKET_TYPE_PLAIN_REQUEST)
            rid = ''

            32.times { |_val| rid << rand(10).to_s }

            add_tlv(TLV_TYPE_REQUEST_ID, rid)
          end
        end

        #
        # Override the function that creates the raw byte stream for
        # sending so that it generates an XOR key, uses it to scramble
        # the serialized TLV content, and then returns the key plus the
        # scrambled data as the payload.
        #
        def to_r
          raw = super
          xor_key = rand(254) + 1
          xor_key |= (rand(254) + 1) << 8
          xor_key |= (rand(254) + 1) << 16
          xor_key |= (rand(254) + 1) << 24
          result = [xor_key].pack('N') + xor_bytes(xor_key, raw)
          result
        end

        #
        # Override the function that reads from a raw byte stream so
        # that the XORing of data is included in the process prior to
        # passing it on to the default functionality that can parse
        # the TLV values.
        #
        def from_r(bytes)
          xor_key = bytes[0, 4].unpack('N')[0]
          super(xor_bytes(xor_key, bytes[4, bytes.length]))
        end

        #
        # Xor a set of bytes with a given DWORD xor key.
        #
        def xor_bytes(xor_key, bytes)
          result = ''
          bytes.bytes.zip([xor_key].pack('V').bytes.cycle).each do |b|
            result << (b[0].ord ^ b[1].ord).chr
          end
          result
        end

        ##
        #
        # Conditionals
        #
        ##

        #
        # Checks to see if the packet is a response.
        #
        def response?
          ((type == PACKET_TYPE_RESPONSE) ||
                  (type == PACKET_TYPE_PLAIN_RESPONSE))
        end

        ##
        #
        # Accessors
        #
        ##

        #
        # Checks to see if the packet's method is equal to the supplied method.
        #
        def method?(method)
          (get_tlv_value(TLV_TYPE_METHOD) == method)
        end

        #
        # Sets the packet's method TLV to the method supplied.
        #
        def method=(method)
          add_tlv(TLV_TYPE_METHOD, method, true)
        end

        #
        # Returns the value of the packet's method TLV.
        #
        def method
          get_tlv_value(TLV_TYPE_METHOD)
        end

        #
        # Checks to see if the packet's result value is equal to the supplied
        # result.
        #
        def result?(result)
          (get_tlv_value(TLV_TYPE_RESULT) == result)
        end

        #
        # Sets the packet's result TLV.
        #
        def result=(result)
          add_tlv(TLV_TYPE_RESULT, result, true)
        end

        #
        # Gets the value of the packet's result TLV.
        #
        def result
          get_tlv_value(TLV_TYPE_RESULT)
        end

        #
        # Gets the value of the packet's request identifier TLV.
        #
        def rid
          get_tlv_value(TLV_TYPE_REQUEST_ID)
        end
      end
    end; end; end
