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
              # Class wrapper around a remote registry key on the remote side
              #
              ###
              class RemoteRegistryKey
                #
                # Initializes an instance of a registry key using the supplied properties
                # and HKEY handle from the server.
                #
                def initialize(client, target_host, root_key, hkey)
                  self.client   = client
                  self.root_key = root_key
                  self.target_host = target_host
                  self.hkey = hkey

                  # Ensure the remote object is closed when all references are removed
                  ObjectSpace.define_finalizer(self, self.class.finalize(client, hkey))
                end

                def self.finalize(client, hkey)
                  proc { close(client, hkey) }
                end

                ##
                #
                # Enumerators
                #
                ##

                #
                # Enumerates all of the child keys within this registry key.
                #
                def each_key(&block)
                  enum_key.each(&block)
                end

                #
                # Enumerates all of the child values within this registry key.
                #
                def each_value(&block)
                  enum_value.each(&block)
                end

                #
                # Retrieves all of the registry keys that are direct descendents of
                # the class' registry key.
                #
                def enum_key
                  client.sys.registry.enum_key(hkey)
                end

                #
                # Retrieves all of the registry values that exist within the opened
                # registry key.
                #
                def enum_value
                  client.sys.registry.enum_value(hkey)
                end

                ##
                #
                # Registry key interaction
                #
                ##

                #
                # Opens a registry key that is relative to this registry key.
                #
                def open_key(base_key, perm = KEY_READ)
                  client.sys.registry.open_key(hkey, base_key, perm)
                end

                #
                # Creates a registry key that is relative to this registry key.
                #
                def create_key(base_key, perm = KEY_READ)
                  client.sys.registry.create_key(hkey, base_key, perm)
                end

                #
                # Deletes a registry key that is relative to this registry key.
                #
                def delete_key(base_key, recursive = true)
                  client.sys.registry.delete_key(hkey, base_key, recursive)
                end

                #
                # Closes the open key.  This must be called if the registry
                # key was opened.
                #
                def self.close(client, hkey)
                  return client.sys.registry.close_key(hkey) unless hkey.nil?

                  false
                end

                # Instance method for the same
                def close
                  unless hkey.nil?
                    ObjectSpace.undefine_finalizer(self)
                    self.class.close(client, hkey)
                    self.hkey = nil
                  end
                end

                ##
                #
                # Registry value interaction
                #
                ##

                #
                # Sets a value relative to the opened registry key.
                #
                def set_value(name, type, data)
                  client.sys.registry.set_value(hkey, name, type, data)
                end

                #
                # Queries the attributes of the supplied registry value relative to
                # the opened registry key.
                #
                def query_value(name)
                  client.sys.registry.query_value(hkey, name)
                end

                #
                # Queries the class of the specified key
                #
                def query_class
                  client.sys.registry.query_class(hkey)
                end

                #
                # Delete the supplied registry value.
                #
                def delete_value(name)
                  client.sys.registry.delete_value(hkey, name)
                end

                ##
                #
                # Serializers
                #
                ##

                #
                # Returns the path to the key.
                #
                def to_s
                  "\\\\" + target_host + "\\" + root_key.to_s + "\\"
                end

                #
                # The open handle to the key on the server.
                #
                attr_reader   :hkey
                #
                # The root key name, such as HKEY_LOCAL_MACHINE.
                #
                attr_reader   :root_key
                #
                # The remote machine name, such as PDC01
                #
                attr_reader   :target_host

                protected

                attr_accessor :client # :nodoc:
                attr_writer   :hkey, :root_key, :target_host # :nodoc:
              end
            end; end; end; end; end; end; end
