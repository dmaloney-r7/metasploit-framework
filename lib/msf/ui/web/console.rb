# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/ui/text/bidirectional_pipe'
module Msf
  module Ui
    module Web
      ###
      #
      # This class implements a console instance for use by the web interface
      #
      ###

      class WebConsole
        attr_accessor :pipe
        attr_accessor :console
        attr_accessor :console_id
        attr_accessor :last_access
        attr_accessor :framework
        attr_accessor :thread

        # Wrapper class in case we need to extend the pipe
        class WebConsolePipe < Rex::Ui::Text::BidirectionalPipe
          def prompting?
            false
          end
        end

        #
        # Provides some overrides for web-based consoles
        #
        module WebConsoleShell
          def supports_color?
            false
          end
        end

        def initialize(framework, console_id, opts = {})
          # Configure the framework
          self.framework = framework

          # Configure the ID
          self.console_id = console_id

          # Create a new pipe
          self.pipe = WebConsolePipe.new

          # Create a read subscriber
          pipe.create_subscriber('msfweb')

          # Skip database initialization if it is already configured
          if framework.db && framework.db.usable && framework.db.migrated
            opts['SkipDatabaseInit'] = true
          end

          # Initialize the console with our pipe
          self.console = Msf::Ui::Console::Driver.new(
            'msf',
            '>',
            opts.merge('Framework' => self.framework,
                       'LocalInput'  => pipe,
                       'LocalOutput' => pipe,
                       'AllowCommandPassthru' => true,
                       'Resource' => [])
          )

          console.extend(WebConsoleShell)
          console.block_command('irb')

          self.thread = framework.threads.spawn("WebConsoleShell", false) { console.run }

          update_access
        end

        def update_access
          self.last_access = Time.now
        end

        def read
          update_access
          pipe.read_subscriber('msfweb')
        end

        def write(buf)
          update_access
          pipe.write_input(buf)
        end

        def execute(cmd)
          console.run_single(cmd)
        end

        def prompt
          pipe.prompt
        end

        def tab_complete(cmd)
          if console.active_session
            return console.active_session.console.tab_complete(cmd)
          end
          console.tab_complete(cmd)
        end

        def shutdown
          pipe.close
          thread.kill
        end

        def busy
          console.busy
        end

        def session_detach
          if console.active_session
            # background interactive meterpreter channel
            if console.active_session.respond_to?('channels')
              console.active_session.channels.each_value do |ch|
                if ch.respond_to?('interacting') && ch.interacting
                  ch.detach
                  return
                end
              end
            end
            # background session
            console.active_session.completed = true
            console.active_session.detach
          end
        end

        def session_kill
          thread.raise(Interrupt)
        end

        def active_module
          console.active_module
        end

        def active_module=(val)
          console.active_module = val
        end
      end
      end
  end
end
