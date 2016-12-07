# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui'
require 'rex/post/meterpreter'
require 'rex/logging'

module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # This class provides a shell driven interface to the meterpreter client API.
        #
        ###
        class Console
          include Rex::Ui::Text::DispatcherShell

          # Dispatchers
          require 'rex/post/meterpreter/ui/console/interactive_channel'
          require 'rex/post/meterpreter/ui/console/command_dispatcher'
          require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

          #
          # Initialize the meterpreter console.
          #
          def initialize(client)
            if Rex::Compat.is_windows
              super("meterpreter")
            else
              super("%undmeterpreter%clr")
            end

            # The meterpreter client context
            self.client = client

            # Queued commands array
            self.commands = []

            # Point the input/output handles elsewhere
            reset_ui

            enstack_dispatcher(Console::CommandDispatcher::Core)

            # Set up logging to whatever logsink 'core' is using
            unless $dispatcher['meterpreter']
              $dispatcher['meterpreter'] = $dispatcher['core']
            end
          end

          #
          # Called when someone wants to interact with the meterpreter client.  It's
          # assumed that init_ui has been called prior.
          #
          def interact(&block)
            init_tab_complete

            # Run queued commands
            commands.delete_if do |ent|
              run_single(ent)
              true
            end

            # Run the interactive loop
            run do |line|
              # Run the command
              run_single(line)

              # If a block was supplied, call it, otherwise return false
              if block
                yield
              else
                false
              end
            end
          end

          #
          # Interacts with the supplied channel.
          #
          def interact_with_channel(channel)
            channel.extend(InteractiveChannel) unless channel.is_a?(InteractiveChannel) == true
            channel.on_command_proc = on_command_proc if on_command_proc
            channel.on_print_proc   = on_print_proc if on_print_proc
            channel.on_log_proc = method(:log_output) if respond_to?(:log_output, true)

            channel.interact(input, output)
            channel.reset_ui
          end

          #
          # Queues a command to be run when the interactive loop is entered.
          #
          def queue_cmd(cmd)
            commands << cmd
          end

          #
          # Runs the specified command wrapper in something to catch meterpreter
          # exceptions.
          #
          def run_command(dispatcher, method, arguments)
            super
          rescue Timeout::Error
            log_error("Operation timed out.")
          rescue RequestError => info
            log_error(info.to_s)
          rescue Rex::InvalidDestination => e
            log_error(e.message)
          rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
            client.kill
          rescue ::Exception => e
            log_error("Error running command #{method}: #{e.class} #{e}")
          end

          #
          # Logs that an error occurred and persists the callstack.
          #
          def log_error(msg)
            print_error(msg)

            elog(msg, 'meterpreter')

            dlog("Call stack:\n#{$ERROR_POSITION.join("\n")}", 'meterpreter')
          end

          attr_reader :client # :nodoc:

          protected

          attr_writer :client # :nodoc:
          attr_accessor :commands # :nodoc:
        end
      end
    end
  end
end
