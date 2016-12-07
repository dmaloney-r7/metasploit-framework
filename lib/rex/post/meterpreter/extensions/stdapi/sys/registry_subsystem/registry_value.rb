# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/sys/registry'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Sys
            module RegistrySubsystem
              ###
              #
              # Class wrapper around a logical registry value on the remote side.
              #
              ###
              class RegistryValue
                #
                # Initializes a registry value instance that's associated with the supplied
                # server key handle.
                #
                def initialize(client, hkey, name, type = nil, data = nil)
                  self.client = client
                  self.hkey   = hkey
                  self.name   = name
                  self.type   = type
                  self.data   = data
                end

                #
                # Sets the value's data.
                #
                def set(data, type = nil)
                  type = self.type if type.nil?
                  if client.sys.registry.set_value(hkey, name,
                                                   type, data)
                    self.data = data
                    self.type = type

                    return true
                  end

                  false
                end

                #
                # Queries the value's data.
                #
                def query
                  val = client.sys.registry.query_value(hkey, name)

                  unless val.nil?
                    self.data = val.data
                    self.type = val.type
                  end

                  data
                end

                #
                # Deletes the value.
                #
                def delete
                  client.sys.registry.delete_value(hkey, name)
                end

                def type_to_s
                  return "REG_SZ" if type == REG_SZ
                  return "REG_DWORD" if type == REG_DWORD
                  return "REG_BINARY" if type == REG_BINARY
                  return "REG_EXPAND_SZ" if type == REG_EXPAND_SZ
                  return "REG_NONE" if type == REG_NONE
                  nil
                end

                #
                # The remote server key handle.
                #
                attr_reader   :hkey
                #
                # The name of the registry value.
                #
                attr_reader   :name
                #
                # The type of data represented by the registry value.
                #
                attr_reader   :type
                #
                # The arbitrary data stored within the value, if any.
                #
                attr_reader   :data

                protected

                attr_accessor :client # :nodoc:
                attr_writer   :hkey, :name, :type, :data # :nodoc:
              end
            end; end; end; end; end; end; end
