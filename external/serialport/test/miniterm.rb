# frozen_string_literal: true
require "../serialport.so"

if ARGV.size < 4
  STDERR.print <<EOF
  Usage: ruby #{$PROGRAM_NAME} num_port bps nbits stopb
EOF
  exit(1)
end

sp = SerialPort.new(ARGV[0].to_i, ARGV[1].to_i, ARGV[2].to_i, ARGV[3].to_i, SerialPort::NONE)

open("/dev/tty", "r+") do |tty|
  tty.sync = true
  Thread.new do
    loop do
      tty.printf("%c", sp.getc)
    end
  end
  while (l = tty.gets)
    sp.write(l.sub("\n", "\r"))
  end
end

sp.close
