# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # Boolean option.
  #
  ###
  class OptBool < OptBase
    TrueRegex = /^(y|yes|t|1|true)$/i

    def type
      'bool'
    end

    def valid?(value, check_empty: true)
      return false if empty_required_value?(value)

      if !value.nil? &&
         (value.to_s.empty? == false) &&
         value.to_s.match(/^(y|yes|n|no|t|f|0|1|true|false)$/i).nil?
        return false
      end

      true
    end

    def normalize(value)
      if value.nil? || value.to_s.match(TrueRegex).nil?
        false
      else
        true
      end
    end

    def is_true?(value)
      normalize(value)
    end

    def is_false?(value)
      !is_true?(value)
    end
    end
end
