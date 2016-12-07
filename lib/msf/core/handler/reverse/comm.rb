# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/socket'

module Msf
  module Handler
    module Reverse
      ###
      #
      # Implements the reverse Rex::Socket::Comm handlng.
      #
      ###
      module Comm
        def initialize(info = {})
          super

          register_advanced_options(
            [
              OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener'])
            ], Msf::Handler::Reverse::Comm
          )
      end

        def select_comm
          rl_comm = datastore['ReverseListenerComm'].to_s
          case rl_comm
          when 'local'
            comm = ::Rex::Socket::Comm::Local
          when /\A[0-9]+\Z/
            comm = framework.sessions[rl_comm.to_i]
            raise "Reverse Listener Comm (Session #{rl_comm}) does not exist" unless comm
            raise "Reverse Listener Comm (Session #{rl_comm}) does not implement Rex::Socket::Comm" unless comm.is_a? ::Rex::Socket::Comm
          when nil, ''
            comm = nil
          else
            raise "Reverse Listener Comm '#{rl_comm}' is invalid"
          end

          comm
        end

        def via_string_for_ip(ip, comm)
          comm_used = comm
          comm_used ||= Rex::Socket::SwitchBoard.best_comm(ip)
          comm_used ||= Rex::Socket::Comm::Local

          via = if comm_used.respond_to?(:type) && comm_used.respond_to?(:sid)
                  "via the #{comm_used.type} on session #{comm_used.sid}"
                else
                  ""
                end

          via
        end
        end
      end
  end
end
