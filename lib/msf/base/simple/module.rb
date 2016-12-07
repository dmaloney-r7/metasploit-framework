# frozen_string_literal: true
# -*- coding: binary -*-
require 'msf/base'

module Msf
  module Simple
    ###
    #
    # Simple module wrapper that provides some common methods for dealing with
    # modules, such as importing options and other such things.
    #
    ###
    module Module
      #
      # Imports extra options from the supplied hash either as a string or as a
      # hash.
      #
      def _import_extra_options(opts)
        # If options were supplied, import them into the payload's
        # datastore
        if opts['Options']
          datastore.import_options_from_hash(opts['Options'])
        elsif opts['OptionStr']
          datastore.import_options_from_s(opts['OptionStr'])
        end
      end

      def inspect
        "#<Module:#{fullname} datastore=[#{datastore.inspect}]>"
      end

      #
      # Initializes the simplified interface.
      #
      def init_simplified(load_saved_config = true)
        load_config if load_saved_config
      end

      #
      # Populates the datastore from the config file.
      #
      def load_config
        datastore.from_file(Msf::Config.config_file, refname)
      end

      #
      # Saves the module's datastore to the file.
      #
      def save_config
        datastore.to_file(Msf::Config.config_file, refname)
      end
      end
    end
end
