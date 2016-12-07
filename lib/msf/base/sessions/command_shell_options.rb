# frozen_string_literal: true
# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

module Msf
  module Sessions
    module CommandShellOptions
      def initialize(info = {})
        super(info)

        register_advanced_options(
          [
            OptString.new('InitialAutoRunScript', [false, "An initial script to run on session creation (before AutoRunScript)", '']),
            OptString.new('AutoRunScript', [false, "A script to run automatically on session creation.", ''])
          ], self.class
        )
    end

      def on_session(session)
        super

        # Configure input/output to match the payload
        session.user_input  = user_input if user_input
        session.user_output = user_output if user_output
        if platform && platform.is_a?(Msf::Module::PlatformList)
          session.platform = platform.platforms.first.realname.downcase
        end
        if platform && platform.is_a?(Msf::Module::Platform)
          session.platform = platform.realname.downcase
        end

        if arch
          session.arch = if arch.is_a?(Array)
                           arch.join('')
                         else
                           arch
                         end
        end
        end
      end
  end
end
