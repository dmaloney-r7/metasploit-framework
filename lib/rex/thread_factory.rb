# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  ###
  #
  # This class provides a wrapper around Thread.new that can provide
  # additional features if a corresponding thread provider is set.
  #
  ###

  class ThreadFactory
    @@provider = nil

    def self.provider=(val)
      @@provider = val
    end

    def self.spawn(name, crit, *args, &block)
      if @@provider
        if block
          @@provider.spawn(name, crit, *args) { |*args_copy| block.call(*args_copy) }
        else
          @@provider.spawn(name, crit, *args)
        end
      else
        t = nil
        t = if block
              ::Thread.new(*args) { |*args_copy| block.call(*args_copy) }
            else
              ::Thread.new(*args)
            end
        t[:tm_name] = name
        t[:tm_crit] = crit
        t[:tm_time] = Time.now
        t[:tm_call] = caller
        t
      end
      end
  end
end
