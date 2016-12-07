# frozen_string_literal: true
require 'mkmf'

printf("checking for OS... ")
STDOUT.flush
os = /-([a-z]+)/.match(RUBY_PLATFORM)[1]
puts(os)
$CFLAGS += " -D#{os}"

unless (os == 'mswin') || (os == 'bccwin')
  exit(1) if !have_header("termios.h") || !have_header("unistd.h")
end

create_makefile("serialport")
