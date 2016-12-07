#!/usr/bin/env ruby
# frozen_string_literal: true
#
# fix up the assembly based on the debug.exe transcript
#
# Joshua J. Drake
#

dtrans = nil
File.open("woop.txt", "rb") do |fd|
  dtrans = fd.read(fd.stat.size)
end

asm = nil
File.open("h2b.com.dbg.in", "rb") do |fd|
  asm = fd.read(fd.stat.size)
end

# extract label addresses
addrs = {}
dtrans.each_line do |ln|
  next unless ln =~ /;[^ ].*:/
  parts = ln.split(' ')
  label = parts[1]
  label = label.slice(1, label.index(':') - 1)
  addr = parts[0].split(':')[1].to_i(16)
  # puts "%s => %x" % [label, addr]
  one = { label => addr }
  addrs.merge!(one)
end
# puts addrs.inspect

# replace calls, jmps, and read/write handle/filename references
replaces = []
asm.each_line do |ln|
  if ln =~ /call /
    parts = ln.split(' ')
    if (parts[0] == "call") && (parts[2] == ";call")
      old = parts[1]
      func = parts[3]
      new = addrs[func]
      # puts "%32s: %s -> %x" % [func, old, new]
      replaces << [func, old, new.to_s(16)]
    end
  end

  if ln =~ /\(jmp\)/
    parts = ln.split(' ')
    if (parts[0][0, 1] == "j") && (parts[2][0, 2] == ";j") && (parts[4] == "(jmp)")
      old = parts[1]
      func = parts[3]
      new = addrs[func]
      # puts "%32s: %s -> %x" % [func, old, new]
      replaces << [func, old, new.to_s(16)]
    end
  end

  next unless ln =~ /;(read|write)_(handle|filename)=/
  parts = ln.split(' ')
  next unless parts[0] == "mov"
  parts2 = parts[2].split('=')
  label = parts2[0]
  label.slice!(0, 1)
  old = parts2[1]
  new = addrs[label]
  # puts "%32s: %s -> %x" % [label, old, new]
  replaces << [label, old, new.to_s(16)]
end

# replace the stuff
replaces.uniq!
replaces.each do |arr|
  # puts "%32s: %s -> %s" % arr
  asm.gsub!(arr[1], arr[2])
end

print asm
