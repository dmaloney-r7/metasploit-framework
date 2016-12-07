# frozen_string_literal: true
# -*- coding: binary -*-
module Msf
  module Session
    module Provider
      ###
      #
      # This interface is to be implemented by a session that is only capable of
      # providing an interface to a single command shell.
      #
      ###
      module SingleCommandShell
        #
        # Initializes the command shell.
        #
        def shell_init
          raise NotImplementedError
        end

        #
        # Reads data from the command shell.
        #
        def shell_read(_length = nil)
          raise NotImplementedError
        end

        #
        # Writes data to the command shell.
        #
        def shell_write(_buf)
          raise NotImplementedError
        end

        #
        # Closes the command shell.
        #
        def shell_close
          raise NotImplementedError
        end

        #
        # Read data until we find the token
        #
        def shell_read_until_token(token, wanted_idx = 0, timeout = 10)
          parts_needed = if wanted_idx == 0
                           2
                         else
                           1 + (wanted_idx * 2)
                         end

          # Read until we get the data between two tokens or absolute timeout.
          begin
            ::Timeout.timeout(timeout) do
              buf = ''
              idx = nil
              loop do
                next unless (tmp = shell_read(-1, 2))
                buf << tmp

                # see if we have the wanted idx
                parts = buf.split(token, -1)
                next unless parts.length == parts_needed
                # cause another prompt to appear (just in case)
                shell_write("\n")
                return parts[wanted_idx]
              end
            end
          rescue
            # nothing, just continue
          end

          # failed to get any data or find the token!
          nil
        end

        def shell_command_token(cmd, timeout = 10)
          output = if platform == 'windows'
                     shell_command_token_win32(cmd, timeout)
                   else
                     shell_command_token_unix(cmd, timeout)
                   end
          output
        end

        #
        # Explicitly run a single command and return the output.
        # This version uses a marker to denote the end of data (instead of a timeout).
        #
        def shell_command_token_unix(cmd, timeout = 10)
          # read any pending data
          buf = shell_read(-1, 0.01)
          set_shell_token_index(timeout)
          token = ::Rex::Text.rand_text_alpha(32)

          # Send the command to the session's stdin.
          shell_write(cmd + ";echo #{token}\n")
          shell_read_until_token(token, @shell_token_index, timeout)
        end

        # NOTE: if the session echoes input we don't need to echo the token twice.
        # This setting will persist for the duration of the session.
        def set_shell_token_index(timeout)
          return @shell_token_index if @shell_token_index
          token = ::Rex::Text.rand_text_alpha(32)
          numeric_token = rand(0xffffffff) + 1
          cmd = "echo #{numeric_token}"
          shell_write(cmd + ";echo #{token}\n")
          res = shell_read_until_token(token, 0, timeout)
          @shell_token_index = if res.to_i == numeric_token
                                 0
                               else
                                 1
                               end
        end

        #
        # Explicitly run a single command and return the output.
        # This version uses a marker to denote the end of data (instead of a timeout).
        #
        def shell_command_token_win32(cmd, timeout = 10)
          # read any pending data
          buf = shell_read(-1, 0.01)
          token = ::Rex::Text.rand_text_alpha(32)

          # Send the command to the session's stdin.
          # NOTE: if the session echoes input we don't need to echo the token twice.
          shell_write(cmd + "&echo #{token}\n")
          shell_read_until_token(token, 1, timeout)
        end
        end
      end
  end
end
