# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/meterpreter/inbound_packet_handler'

module Rex
  module Post
    module Meterpreter
      #
      # The various types of channels
      #
      CHANNEL_CLASS_STREAM = 1
      CHANNEL_CLASS_DATAGRAM   = 2
      CHANNEL_CLASS_POOL       = 3

      #
      # The various flags that can affect how the channel operates
      #
      #   CHANNEL_FLAG_SYNCHRONOUS
      #      Specifies that I/O requests on the channel are blocking.
      #
      #   CHANNEL_FLAG_COMPRESS
      #      Specifies that I/O requests on the channel have their data zlib compressed.
      #
      CHANNEL_FLAG_SYNCHRONOUS = (1 << 0)
      CHANNEL_FLAG_COMPRESS    = (1 << 1)

      #
      # The core types of direct I/O requests
      #
      CHANNEL_DIO_READ         = 'read'
      CHANNEL_DIO_WRITE        = 'write'
      CHANNEL_DIO_CLOSE        = 'close'

      ###
      #
      # The channel class represents a logical data pipe that exists between the
      # client and the server.  The purpose and behavior of the channel depends on
      # which type it is.  The three basic types of channels are streams, datagrams,
      # and pools.  Streams are basically equivalent to a TCP connection.
      # Bidirectional, connection-oriented streams.  Datagrams are basically
      # equivalent to a UDP session.  Bidirectional, connectionless.  Pools are
      # basically equivalent to a uni-directional connection, like a file handle.
      # Pools denote channels that only have requests flowing in one direction.
      #
      ###
      class Channel
        # Class modifications to support global channel message
        # dispatching without having to register a per-instance handler
        class << self
          include Rex::Post::Meterpreter::InboundPacketHandler

          # Class request handler for all channels that dispatches requests
          # to the appropriate class instance's DIO handler
          def request_handler(client, packet)
            cid = packet.get_tlv_value(TLV_TYPE_CHANNEL_ID)

            # No channel identifier, then drop it
            return false if cid.nil?

            channel = client.find_channel(cid)

            # No valid channel context? The channel may not be registered yet
            return false if channel.nil?

            dio = channel.dio_map(packet.method)

            # Supported DIO request? Dump it.
            return true if dio.nil?

            # Call the channel's dio handler and return success or fail
            # based on what happens
            channel.dio_handler(dio, packet)
          end
        end

        ##
        #
        # Factory
        #
        ##

        #
        # Creates a logical channel between the client and the server
        # based on a given type.
        #
        def self.create(client, type = nil, klass = nil,
                        flags = CHANNEL_FLAG_SYNCHRONOUS, addends = nil)
          request = Packet.create_request('core_channel_open')

          # Set the type of channel that we're allocating
          request.add_tlv(TLV_TYPE_CHANNEL_TYPE, type) unless type.nil?

          # If no factory class was provided, use the default native class
          klass = self if klass.nil?

          request.add_tlv(TLV_TYPE_CHANNEL_CLASS, klass.cls)
          request.add_tlv(TLV_TYPE_FLAGS, flags)
          request.add_tlvs(addends)

          # Transmit the request and wait for the response
          response = client.send_request(request)
          cid      = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)

          return nil unless cid

          # Create the channel instance
          channel = klass.new(client, cid, type, flags)

          channel
        end

        ##
        #
        # Constructor
        #
        ##

        #
        # Initializes the instance's attributes, such as client context,
        # class identifier, type, and flags.
        #
        def initialize(client, cid, type, flags)
          self.client = client
          self.cid    = cid
          self.type   = type
          self.flags  = flags

          # Add this instance to the list
          client.add_channel(self) if cid && client

          # Ensure the remote object is closed when all references are removed
          ObjectSpace.define_finalizer(self, self.class.finalize(client, cid))
        end

        def self.finalize(client, cid)
          proc { _close(client, cid) }
        end

        ##
        #
        # Channel interaction
        #
        ##

        #
        # Wrapper around the low-level channel read operation.
        #
        def read(length = nil, addends = nil)
          _read(length, addends)
        end

        #
        # Reads data from the remote half of the channel.
        #
        def _read(length = nil, addends = nil)
          raise IOError, "Channel has been closed.", caller if cid.nil?

          request = Packet.create_request('core_channel_read')

          if length.nil?
            # Default block size to a higher amount for passive dispatcher
            length = client.passive_service ? (1024 * 1024) : 65536
          end

          request.add_tlv(TLV_TYPE_CHANNEL_ID, cid)
          request.add_tlv(TLV_TYPE_LENGTH, length)
          request.add_tlvs(addends)

          begin
            response = client.send_request(request)
          rescue
            return nil
          end

          # If the channel is in synchronous mode, the response should contain
          # data that was read from the remote side of the channel
          if flag?(CHANNEL_FLAG_SYNCHRONOUS)
            data = response.get_tlv(TLV_TYPE_CHANNEL_DATA)

            return data.value unless data.nil?
          else
            raise NotImplementedError, "Asynchronous channel mode is not implemented", caller
          end

          nil
        end

        #
        # Wrapper around the low-level write.
        #
        def write(buf, length = nil, addends = nil)
          _write(buf, length, addends)
        end

        #
        # Writes data to the remote half of the channel.
        #
        def _write(buf, length = nil, addends = nil)
          raise IOError, "Channel has been closed.", caller if cid.nil?

          request = Packet.create_request('core_channel_write')

          # Truncation and celebration
          if !length.nil? &&
             (buf.length >= length)
            buf = buf[0..length]
          else
            length = buf.length
          end

          # Populate the request
          request.add_tlv(TLV_TYPE_CHANNEL_ID, cid)

          cdata = request.add_tlv(TLV_TYPE_CHANNEL_DATA, buf)
          if (flags & CHANNEL_FLAG_COMPRESS) == CHANNEL_FLAG_COMPRESS
            cdata.compress = true
          end

          request.add_tlv(TLV_TYPE_LENGTH, length)
          request.add_tlvs(addends)

          response = client.send_request(request)
          written  = response.get_tlv(TLV_TYPE_LENGTH)

          written.nil? ? 0 : written.value
        end

        #
        # Wrapper around the low-level close.
        #
        def close(addends = nil)
          _close(addends)
        end

        #
        # Close the channel for future writes.
        #
        def close_write
          _close
        end

        #
        # Close the channel for future reads.
        #
        def close_read
          _close
        end

        #
        # Closes the channel.
        #
        def self._close(client, cid, addends = nil)
          raise IOError, "Channel has been closed.", caller if cid.nil?

          request = Packet.create_request('core_channel_close')

          # Populate the request
          request.add_tlv(TLV_TYPE_CHANNEL_ID, cid)
          request.add_tlvs(addends)

          client.send_request(request, nil)

          # Disassociate this channel instance
          client.remove_channel(cid)

          true
        end

        def _close(addends = nil)
          unless cid.nil?
            ObjectSpace.undefine_finalizer(self)
            self.class._close(client, cid, addends)
            self.cid = nil
          end
        end

        #
        # Enables or disables interactive mode.
        #
        def interactive(tf = true, addends = nil)
          raise IOError, "Channel has been closed.", caller if cid.nil?

          request = Packet.create_request('core_channel_interact')

          # Populate the request
          request.add_tlv(TLV_TYPE_CHANNEL_ID, cid)
          request.add_tlv(TLV_TYPE_BOOL, tf)
          request.add_tlvs(addends)

          client.send_request(request)

          true
        end

        ##
        #
        # Direct I/O
        #
        ##

        #
        # Handles dispatching I/O requests based on the request packet.
        # The default implementation does nothing with direct I/O requests.
        #
        def dio_handler(dio, packet)
          if dio == CHANNEL_DIO_READ
            length = packet.get_tlv_value(TLV_TYPE_LENGTH)

            return dio_read_handler(packet, length)
          elsif dio == CHANNEL_DIO_WRITE
            data = packet.get_tlv_value(TLV_TYPE_CHANNEL_DATA)

            return dio_write_handler(packet, data)
          elsif dio == CHANNEL_DIO_CLOSE
            return dio_close_handler(packet)
          end
          false
        end

        #
        # Stub read handler.
        #
        def dio_read_handler(_packet, _length)
          true
        end

        #
        # Stub write handler.
        #
        def dio_write_handler(_packet, _data)
          true
        end

        #
        # Stub close handler.
        #
        def dio_close_handler(_packet)
          client.remove_channel(cid)

          # Trap IOErrors as parts of the channel may have already been closed
          begin
            cleanup
          rescue IOError
          end

          # No more channel action, foo.
          self.cid = nil

          true
        end

        #
        # Maps packet request methods to DIO request identifiers on a
        # per-instance basis as other instances may add custom dio
        # handlers.
        #
        def dio_map(method)
          if method == 'core_channel_read'
            return CHANNEL_DIO_READ
          elsif method == 'core_channel_write'
            return CHANNEL_DIO_WRITE
          elsif method == 'core_channel_close'
            return CHANNEL_DIO_CLOSE
          end

          nil
        end

        ##
        #
        # Conditionals
        #
        ##

        #
        # Checks to see if a flag is set on the instance's flags attribute.
        #
        def flag?(flag)
          ((flags & flag) == flag)
        end

        #
        # Returns whether or not the channel is operating synchronously.
        #
        def synchronous?
          (flags & CHANNEL_FLAG_SYNCHRONOUS)
        end

        #
        # The unique channel identifier.
        #
        attr_reader   :cid
        #
        # The type of channel.
        #
        attr_reader   :type
        #
        # The class of channel (stream, datagram, pool).
        #
        attr_reader   :cls
        #
        # Any channel-specific flag, like synchronous IO.
        #
        attr_reader   :flags
        #
        # Any channel-specific parameters.
        #
        attr_accessor :params
        #
        # The associated meterpreter client instance
        #
        attr_accessor :client

        protected

        attr_writer :cid, :type, :cls, :flags # :nodoc:

        #
        # Cleans up any lingering resources
        #
        def cleanup
        end
      end
    end; end; end
