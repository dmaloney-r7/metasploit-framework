# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  autoload :Opt, 'msf/core/opt'

  autoload :OptBase, 'msf/core/opt_base'

  autoload :OptAddress, 'msf/core/opt_address'
  autoload :OptAddressRange, 'msf/core/opt_address_range'
  autoload :OptBool, 'msf/core/opt_bool'
  autoload :OptEnum, 'msf/core/opt_enum'
  autoload :OptInt, 'msf/core/opt_int'
  autoload :OptPath, 'msf/core/opt_path'
  autoload :OptPort, 'msf/core/opt_port'
  autoload :OptRaw, 'msf/core/opt_raw'
  autoload :OptRegexp, 'msf/core/opt_regexp'
  autoload :OptString, 'msf/core/opt_string'

  #
  # The options purpose in life is to associate named options with arbitrary
  # values at the most simplistic level. Each {Msf::Module} contains an
  # OptionContainer that is used to hold the various options that the module
  # depends on. Example of options that are stored in the OptionContainer are
  # rhost and rport for payloads or exploits that need to connect to a host
  # and port, for instance.
  #
  # The core supported option types are:
  #
  # * {OptString}  - Multi-byte character string
  # * {OptRaw}     - Multi-byte raw string
  # * {OptBool}    - Boolean true or false indication
  # * {OptPort}    - TCP/UDP service port
  # * {OptAddress} - IP address or hostname
  # * {OptPath}    - Path name on disk or an Object ID
  # * {OptInt}     - An integer value
  # * {OptEnum}    - Select from a set of valid values
  # * {OptAddressRange} - A subnet or range of addresses
  # * {OptRegexp}  - Valid Ruby regular expression
  #
  class OptionContainer < Hash
    #
    # Merges in the supplied options and converts them to a OptBase
    # as necessary.
    #
    def initialize(opts = {})
      self.sorted = []

      add_options(opts)
    end

    #
    # Return the value associated with the supplied name.
    #
    def [](name)
      get(name)
    end

    #
    # Return the option associated with the supplied name.
    #
    def get(name)
      return fetch(name)
    rescue
    end

    #
    # Returns whether or not the container has any options,
    # excluding advanced (and evasions).
    #
    def has_options?
      each_option do |_name, opt|
        return true if opt.advanced? == false
      end

      false
    end

    #
    # Returns whether or not the container has any advanced
    # options.
    #
    def has_advanced_options?
      each_option do |_name, opt|
        return true if opt.advanced? == true
      end

      false
    end

    #
    # Returns whether or not the container has any evasion
    # options.
    #
    def has_evasion_options?
      each_option do |_name, opt|
        return true if opt.evasion? == true
      end

      false
    end

    #
    # Removes an option.
    #
    def remove_option(name)
      delete(name)
      sorted.each_with_index do |e, idx|
        sorted[idx] = nil if e[0] == name
      end
      sorted.delete(nil)
    end

    #
    # Adds one or more options.
    #
    def add_options(opts, owner = nil, advanced = false, evasion = false)
      return false if opts.nil?

      if opts.is_a?(Array)
        add_options_array(opts, owner, advanced, evasion)
      else
        add_options_hash(opts, owner, advanced, evasion)
      end
    end

    #
    # Add options from a hash of names.
    #
    def add_options_hash(opts, owner = nil, advanced = false, evasion = false)
      opts.each_pair do |name, opt|
        add_option(opt, name, owner, advanced, evasion)
      end
    end

    #
    # Add options from an array of option instances or arrays.
    #
    def add_options_array(opts, owner = nil, advanced = false, evasion = false)
      opts.each do |opt|
        add_option(opt, nil, owner, advanced, evasion)
      end
    end

    #
    # Adds an option.
    #
    def add_option(option, name = nil, owner = nil, advanced = false, evasion = false)
      if option.is_a?(Array)
        option = option.shift.new(name, option)
      elsif !option.is_a?(OptBase)
        raise ArgumentError,
              "The option named #{name} did not come in a compatible format.",
              caller
      end

      option.advanced = advanced
      option.evasion  = evasion
      option.owner    = owner

      store(option.name, option)

      # Re-calculate the sorted list
      self.sorted = sort
    end

    #
    # Alias to add advanced options that sets the proper state flag.
    #
    def add_advanced_options(opts, owner = nil)
      return false if opts.nil?

      add_options(opts, owner, true)
    end

    #
    # Alias to add evasion options that sets the proper state flag.
    #
    def add_evasion_options(opts, owner = nil)
      return false if opts.nil?

      add_options(opts, owner, false, true)
    end

    #
    # Make sures that each of the options has a value of a compatible
    # format and that all the required options are set.
    #
    def validate(datastore)
      errors = []

      each_pair do |name, option|
        if !option.valid?(datastore[name])
          errors << name
          # If the option is valid, normalize its format to the correct type.
        elsif (val = option.normalize(datastore[name])) != nil
          # This *will* result in a module that previously used the
          # global datastore to have its local datastore set, which
          # means that changing the global datastore and re-running
          # the same module will now use the newly-normalized local
          # datastore value instead. This is mostly mitigated by
          # forcing a clone through mod.replicant, but can break
          # things in corner cases.
          datastore[name] = val
        end
      end

      if errors.empty? == false
        raise OptionValidateError.new(errors),
              "One or more options failed to validate", caller
      end

      true
    end

    #
    # Creates string of options that were used from the datastore in VAR=VAL
    # format separated by commas.
    #
    def options_used_to_s(datastore)
      used = ''

      each_pair do |name, _option|
        next if datastore[name].nil?

        used += ", " unless used.empty?
        used += "#{name}=#{datastore[name]}"
      end

      used
    end

    #
    # Enumerates each option name
    #
    def each_option(&block)
      each_pair(&block)
    end

    #
    # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
    #    "can't add a new key into hash during iteration"
    #
    def each(&block)
      list = []
      keys.sort.each do |sidx|
        list << [sidx, self[sidx]]
      end
      list.each(&block)
    end

    #
    # Merges the options in this container with another option container and
    # returns the sorted results.
    #
    def merge_sort(other_container)
      result = dup

      other_container.each do |name, opt|
        result[name] = opt if result.get(name).nil?
      end

      result.sort
    end

    #
    # The sorted array of options.
    #
    attr_reader :sorted

    protected

    attr_writer :sorted # :nodoc:
  end
end
