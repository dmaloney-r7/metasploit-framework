# frozen_string_literal: true
module Msf::Module::Network
  #
  # The default communication subsystem for this module.  We may need to move
  # this somewhere else.
  #
  def comm
    Rex::Socket::Comm::Local
  end

  #
  # Indicates whether the module supports IPv6. This is true by default,
  # but certain modules require additional work to be compatible or are
  # hardcoded in terms of application support and should be skipped.
  #
  def support_ipv6?
    true
  end

  #
  # Returns the address of the last target host (rough estimate)
  #
  def target_host
    respond_to?('rhost') ? rhost : datastore['RHOST']
  end

  #
  # Returns the address of the last target port (rough estimate)
  #
  def target_port
    respond_to?('rport') ? rport : datastore['RPORT']
  end
end
