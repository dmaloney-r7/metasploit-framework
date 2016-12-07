#!/usr/bin/env ruby
# frozen_string_literal: true
#
# $Id$
#
# This script lists each module by its licensing terms
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

def lic_short(l)
  l = l[0] if l.class == Array

  case l
  when MSF_LICENSE
    'MSF'
  when GPL_LICENSE
    'GPL'
  when BSD_LICENSE
    'BSD'
  when ARTISTIC_LICENSE
    'ART'
  else
    'UNK'
  end
end

sort = 0
filter = 'All'
filters = ['all', 'exploit', 'payload', 'post', 'nop', 'encoder', 'auxiliary']
reg = 0
regex = ''

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-s" => [ false, "Sort by License instead of Module Type."],
  "-r" => [ false, "Reverse Sort"],
  "-f" => [ true, "Filter based on Module Type [#{filters.map(&:capitalize).join(', ')}] (Default = All)."],
  "-x" => [ true, "String or RegEx to try and match against the License Field"]
)

opts.parse(ARGV) do |opt, _idx, val|
  case opt
  when "-h"
    puts "\nMetasploit Script for Displaying Module License information."
    puts "=========================================================="
    puts opts.usage
    exit
  when "-s"
    puts "Sorting by License"
    sort = 1
  when "-r"
    puts "Reverse Sorting"
    sort = 2
  when "-f"
    unless filters.include?(val.downcase)
      puts "Invalid Filter Supplied: #{val}"
      puts "Please use one of these: #{filters.map(&:capitalize).join(', ')}"
      exit
    end
    puts "Module Filter: #{val}"
    filter = val
  when "-x"
    puts "Regex: #{val}"
    reg = 1
    regex = val
  end
end

Indent = '    '

# Always disable the database (we never need it just to list module
# information).
framework_opts = { 'DisableDatabase' => true }

# If the user only wants a particular module type, no need to load the others
unless filter.casecmp('all').zero?
  framework_opts[:module_types] = [ filter.downcase ]
end

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create(framework_opts)

tbl = Rex::Text::Table.new(
  'Header'  => 'Licensed Modules',
  'Indent'  => Indent.length,
  'Columns' => [ 'License', 'Type', 'Name' ]
)

licenses = {}

$framework.modules.each do |name, mod|
  x = mod.new
  lictype = lic_short(x.license)
  if (reg == 0) || lictype =~ /#{regex}/
    tbl << [ lictype, mod.type.capitalize, name ]
  end
end

tbl.sort_rows(0) if sort == 1

if sort == 2
  tbl.sort_rows(1)
  tbl.rows.reverse
end

puts tbl.to_s
