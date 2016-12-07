# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # File system path option.
  #
  ###
  class OptPath < OptBase
    def type
      'path'
    end

    def normalize(value)
      value.nil? ? value : File.expand_path(value)
    end

    def validate_on_assignment?
      false
    end

    # Generally, 'value' should be a file that exists.
    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      if value && !value.empty?
        if value =~ /^memory:\s*([0-9]+)/i
          return false unless check_memory_location(Regexp.last_match(1))
        else
          return false unless File.exist?(File.expand_path(value))
        end
      end
      super
    end

    # The AuthBrute mixin can take a memory address as well --
    # currently, no other OptFile can make use of these objects.
    # TODO: Implement memory:xxx to be more generally useful so
    # the validator on OptFile isn't lying for non-AuthBrute.
    def check_memory_location(id)
      return false unless self.class.const_defined?(:ObjectSpace)
      obj = begin
              ObjectSpace._id2ref(id.to_i)
            rescue
              nil
            end
      return false unless obj.respond_to? :acts_as_file?
      return false unless obj.acts_as_file? # redundant?
      !!obj
    end
  end
end
