# frozen_string_literal: true
# -*- coding: binary -*-

module Msf
  ###
  #
  # Network address option.
  #
  ###
  class OptAddress < OptBase
    def type
      'address'
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return false unless value.is_a?(String) || value.is_a?(NilClass)

      if !value.nil? && (value.empty? == false)
        begin
          getaddr_result = ::Rex::Socket.getaddress(value, true)
          # Covers a wierdcase where an incomplete ipv4 address will have it's
          # missing octets filled in  with 0's. (e.g 192.168 become 192.0.0.168)
          # which does not feel like a legit behaviour
          if value =~ /^\d{1,3}(\.\d{1,3}){1,3}$/
            return false unless value =~ Rex::Socket::MATCH_IPV4
          end
        rescue
          return false
        end
      end

      super
    end
  end
end
