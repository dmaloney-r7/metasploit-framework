#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Write data preceded by little-endian 4-byte size
#

bundle = IO.read(ARGV[0])

data = [bundle.length, bundle].pack('Va*')
STDOUT.write(data)
