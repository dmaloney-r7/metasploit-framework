# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Proto
    module DCERPC
      class Handle
        require 'rex/proto/dcerpc/uuid'

        @@protocols = ['ncacn_ip_tcp', 'ncacn_ip_udp', 'ncacn_np', 'ncacn_http']
        attr_accessor :uuid, :protocol, :address, :options

        # instantiate a handle object, akin to Microsoft's string binding handle by values
        def initialize(uuid, protocol, address, options)
          raise ArgumentError unless Rex::Proto
          raise ArgumentError unless Rex::Proto::DCERPC::UUID.is?(uuid[0])
          raise ArgumentError unless @@protocols.include?(protocol)
          self.uuid = uuid
          self.protocol = protocol
          self.address = address
          self.options = options
        end

        # instantiate a handle object, by parsing a string binding handle
        def self.parse(handle)
          uuid_re = '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
          rev_re = '\d+.\d+'
          proto_re = '(?:' + @@protocols.join('|') + ')'
          re = Regexp.new("(#{uuid_re}):(#{rev_re})\@(#{proto_re}):(.*?)\\[(.*)\\]$", true, 'n')
          match = re.match(handle)
          raise ArgumentError unless match

          uuid = [match[1], match[2]]
          protocol = match[3]
          address = match[4]
          options = match[5].split(',')
          i = Rex::Proto::DCERPC::Handle.new(uuid, protocol, address, options)
          i
        end

        # stringify a handle
        def to_s
          uuid.join(':') + '@' + protocol + ':' + address + '[' + options.join(', ') + ']'
        end
        end
    end
  end
end
