# frozen_string_literal: true
# -*- coding: binary -*-

require 'timeout'
require 'thread'

module Rex
  module Post
    module Meterpreter
      ###
      #
      # This class handles waiting for a response to a given request
      # and the subsequent response association.
      #
      ###
      class PacketResponseWaiter
        # Arbitrary argument to {#completion_routine}
        #
        # @return [Object,nil]
        attr_accessor :completion_param

        # A callback to be called when this waiter is notified of a packet's
        # arrival. If not nil, this will be called with the response packet as first
        # parameter and {#completion_param} as the second.
        #
        # @return [Proc,nil]
        attr_accessor :completion_routine

        # @return [ConditionVariable]
        attr_accessor :cond

        # @return [Mutex]
        attr_accessor :mutex

        # @return [Packet]
        attr_accessor :response

        # @return [Fixnum] request ID to wait for
        attr_accessor :rid

        #
        # Initializes a response waiter instance for the supplied request
        # identifier.
        #
        def initialize(rid, completion_routine = nil, completion_param = nil)
          self.rid      = rid.dup
          self.response = nil

          if completion_routine
            self.completion_routine = completion_routine
            self.completion_param   = completion_param
          else
            self.mutex = Mutex.new
            self.cond  = ConditionVariable.new
          end
        end

        #
        # Checks to see if this waiter instance is waiting for the supplied
        # packet based on its request identifier.
        #
        def waiting_for?(packet)
          (packet.rid == rid)
        end

        #
        # Notifies the waiter that the supplied response packet has arrived.
        #
        # @param response [Packet]
        # @return [void]
        def notify(response)
          if completion_routine
            self.response = response
            completion_routine.call(response, completion_param)
          else
            mutex.synchronize do
              self.response = response
              cond.signal
            end
          end
        end

        #
        # Wait for a given time interval for the response packet to arrive.
        #
        # @param interval [Fixnum,nil] number of seconds to wait, or nil to wait
        #   forever
        # @return [Packet,nil] the response, or nil if the interval elapsed before
        #   receiving one
        def wait(interval)
          interval = nil if interval && (interval == -1)
          mutex.synchronize do
            cond.wait(mutex, interval) if response.nil?
          end
          response
        end
      end
    end; end; end
