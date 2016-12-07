#!/usr/bin/env ruby
# frozen_string_literal: true

toplevel = `git rev-parse --show-toplevel`.strip
infile = "#{toplevel}/.git/config"
outfile = infile
$stderr.puts "Rewriting #{infile}"
data = File.open(infile, 'rb') { |f| f.read f.stat.size }
newdata = ""
data.each_line do |line|
  newdata << line
  case line
  when /^(\s*)fetch\s*=.*remotes\/([^\/]+)\//
    ws = Regexp.last_match(1)
    remote = Regexp.last_match(2)
    pr_line = "fetch = +refs/pull/*/head:refs/remotes/#{remote}/pr/*"
    next if line.strip == pr_line.strip
    if data.include? pr_line
      $stderr.puts "Skipping #{remote}, already present"
      next
    else
      @new_pr_line ||= true
      $stderr.puts "Adding pull request fetch for #{remote}"
      newdata << "#{ws}#{pr_line}\n"
    end
  end
end

if @new_pr_line
  File.open(outfile, 'wb') { |f| f.write newdata }
  $stderr.puts "Wrote #{outfile}"
else
  $stderr.puts "No changes to #{outfile}"
end
