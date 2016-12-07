#!/usr/bin/env ruby
# frozen_string_literal: true
#
# $Id$
#
# This script lists each module by the default ports it uses
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$LOAD_PATH.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
require 'msfenv'

$LOAD_PATH.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'msf/ui'
require 'msf/base'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

all_modules = $framework.exploits.merge($framework.auxiliary)
all_ports = {}

all_modules.each_module do |_name, mod|
  x = mod.new
  ports = []

  ports << x.datastore['RPORT'] if x.datastore['RPORT']

  if x.respond_to?('autofilter_ports')
    x.autofilter_ports.each do |rport|
      ports << rport
    end
  end
  ports = ports.map(&:to_i)
  ports.uniq!
  ports.sort { |a, b| a <=> b }.each do |rport|
    # Just record the first occurance.
    all_ports[rport] = x.fullname unless all_ports[rport]
  end
end

all_ports.sort.each do |k, v|
  puts "%5s # %s" % [k, v]
end
