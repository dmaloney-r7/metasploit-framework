#!/usr/bin/env ruby
# frozen_string_literal: true

Dir.open(".").entries.grep(/.aiff$/).each do |inp|
  out = inp.gsub(".aiff", ".wav")
  system("sox #{inp} #{out}")
end
