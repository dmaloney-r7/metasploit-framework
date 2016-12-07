# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # Mixin that is meant to extend the base channel class from meterpreter in a
        # manner that adds interactive capabilities.
        #
        ###
        module Console::InteractiveChannel
          include Rex::Ui::Interactive

          #
          # Interacts with self.
          #
          def _interact
            # If the channel has a left-side socket, then we can interact with it.
            if lsock
              interactive(true)

              interact_stream(self)

              interactive(false)
            else
              print_error("Channel #{cid} does not support interaction.")

              self.interacting = false
            end
          end

          #
          # Called when an interrupt is sent.
          #
          def _interrupt
            prompt_yesno("Terminate channel #{cid}?")
          end

          #
          # Suspends interaction with the channel.
          #
          def _suspend
            # Ask the user if they would like to background the session
            if prompt_yesno("Background channel #{cid}?") == true
              interactive(false)

              self.interacting = false
            end
          end

          #
          # Closes the channel like it aint no thang.
          #
          def _interact_complete
            interactive(false)

            close
          rescue IOError
          end

          #
          # Reads data from local input and writes it remotely.
          #
          def _stream_read_local_write_remote(_channel)
            data = user_input.gets
            return unless data

            on_command_proc&.call(data.strip)
            write(data)
          end

          #
          # Reads from the channel and writes locally.
          #
          def _stream_read_remote_write_local(_channel)
            data = lsock.sysread(16384)

            on_print_proc&.call(data.strip)
            on_log_proc&.call(data.strip)
            user_output.print(data)
          end

          #
          # Returns the remote file descriptor to select on
          #
          def _remote_fd(_stream)
            lsock
          end

          attr_accessor :on_log_proc
          end
        end
    end
  end
end
