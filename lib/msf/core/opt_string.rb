# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # Mult-byte character string option.
  #
  ###
  class OptString < OptBase
    def type
      'string'
    end

    def validate_on_assignment?
      false
    end

    def normalize(value)
      if value.to_s =~ /^file:(.*)/
        path = Regexp.last_match(1)
        begin
          value = File.read(path)
        rescue ::Errno::ENOENT, ::Errno::EISDIR
          value = nil
        end
      end
      value
    end

    def valid?(value = self.value, check_empty: true)
      value = normalize(value)
      return false if check_empty && empty_required_value?(value)
      super
    end
  end
end
