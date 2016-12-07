# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Proto
    ##
    #
    # Steam protocol support, taken from https://developer.valvesoftware.com/wiki/Server_queries
    #
    ##
    module Steam
      # The Steam header ussed when the message is fragmented.
      FRAGMENTED_HEADER = 0xFFFFFFFE
      # The Steam header ussed when the message is not fragmented.
      UNFRAGMENTED_HEADER = 0xFFFFFFFF

      # Decodes a Steam response message.
      #
      # @param message [String] the message to decode
      # @return [Array] the message type and body
      def decode_message(message)
        # minimum size is header (4) + type (1)
        return if message.length < 5
        header, type = message.unpack('NC')
        # TODO: handle fragmented responses
        return if header != UNFRAGMENTED_HEADER
        [type, message[5, message.length]]
      end

      # Encodes a Steam message.
      #
      # @param type [String, Fixnum] the message type
      # @param body [String] the message body
      # @return [String] the encoded Steam message
      def encode_message(type, body)
        if type.is_a? Integer
          type_num = type
        elsif type.is_a? String
          type_num = type.ord
        else
          raise ArgumentError, 'type must be a String or Fixnum'
        end

        [UNFRAGMENTED_HEADER, type_num ].pack('NC') + body
      end

      # Builds an A2S_INFO message
      #
      # @return [String] the A2S_INFO message
      def a2s_info
        encode_message('T', "Source Engine Query\x00")
      end

      # Decodes an A2S_INFO response message
      #
      # @param response [String] the A2S_INFO resposne to decode
      # @return [Hash] the fields extracted from the response
      def a2s_info_decode(response)
        # abort if it is impossibly short
        return nil if response.length < 19
        message_type, body = decode_message(response)
        # abort if it isn't a valid Steam response
        return nil if message_type != 0x49 # 'I'
        info = {}
        info[:version], info[:name], info[:map], info[:folder], info[:game_name],
          info[:game_id], players, players_max, info[:bots],
          type, env, vis, vac, info[:game_version], _edf = body.unpack("CZ*Z*Z*Z*SCCCCCCCZ*C")

        # translate type
        server_type = case type
                      when 100 # d
                        'Dedicated'
                      when 108 # l
                        'Non-dedicated'
                      when 112 # p
                        'SourceTV relay (proxy)'
                      else
                        "Unknown (#{type})"
                      end
        info[:type] = server_type

        # translate environment
        case env
        when 108 # l
          server_env = 'Linux'
        when 119 # w
          server_env = 'Windows'
        when 109 # m
        when 111 # o
          server_env = 'Mac'
        else
          server_env = "Unknown (#{env})"
        end
        info[:environment] = server_env

        # translate visibility
        server_vis = case vis
                     when 0
                       'public'
                     when 1
                       'private'
                     else
                       "Unknown (#{vis})"
                     end
        info[:visibility] = server_vis

        # translate VAC
        server_vac = case vac
                     when 0
                       'unsecured'
                     when 1
                       'secured'
                     else
                       "Unknown (#{vac})"
                     end
        info[:VAC] = server_vac

        # format players/max
        info[:players] = "#{players}/#{players_max}"

        # TODO: parse EDF
        info
      end
    end
  end
end
