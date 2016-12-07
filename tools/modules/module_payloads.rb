#!/usr/bin/env ruby
# frozen_string_literal: true
#
# $Id$
#
# This script lists each exploit module by its compatible payloads
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

$framework.exploits.each_module do |_name, mod|
  x = mod.new

  x.compatible_payloads.map do |n, _m|
    puts "#{x.refname.ljust 40} - #{n}"
  end
end
