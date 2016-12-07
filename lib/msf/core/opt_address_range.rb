# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # Network address range option.
  #
  ###
  class OptAddressRange < OptBase
    def type
      'addressrange'
    end

    def validate_on_assignment?
      false
    end

    def normalize(value)
      return nil unless value.is_a?(String)
      if value =~ /^file:(.*)/
        path = Regexp.last_match(1)
        return false if !File.exist?(path) || File.directory?(path)
        return File.readlines(path).map(&:strip).join(" ")
      elsif value =~ /^rand:(.*)/
        count = Regexp.last_match(1).to_i
        return false if count < 1
        ret = ''
        count.times do
          ret << " " unless ret.empty?
          ret << [ rand(0x100000000) ].pack("N").unpack("C*").map(&:to_s).join(".")
        end
        return ret
      end
      value
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return false unless value.is_a?(String) || value.is_a?(NilClass)

      if !value.nil? && (value.empty? == false)
        normalized = normalize(value)
        return false if normalized.nil?
        walker = Rex::Socket::RangeWalker.new(normalized)
        return false if !walker || !walker.valid?
      end

      super
    end
  end
end
