# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # Enum option.
  #
  ###
  class OptEnum < OptBase
    def type
      'enum'
    end

    def valid?(value = self.value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return true if value.nil? && !required?

      (value && enums.include?(value.to_s))
    end

    def normalize(value = self.value)
      return nil unless valid?(value)
      value.to_s
    end

    def desc=(value)
      self.desc_string = value

      desc
    end

    def desc
      str = enums.join(', ') if enums
      "#{desc_string || ''} (Accepted: #{str})"
    end

    protected

    attr_accessor :desc_string # :nodoc:
  end
end
