# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Post
    module Meterpreter
      ###
      #
      # Mixin that provides stubs for handling inbound packets
      #
      ###
      module InboundPacketHandler
        #
        # Stub request handler that returns false by default.
        #
        def request_handler(_client, _packet)
          false
        end

        #
        # Stub response handler that returns false by default.
        #
        def response_handler(_client, _packet)
          false
        end
        end
      end; end; end
