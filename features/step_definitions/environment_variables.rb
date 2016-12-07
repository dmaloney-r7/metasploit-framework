# frozen_string_literal: true
Given /^I unset the environment variables:$/ do |table|
  table.hashes.each do |row|
    variable = row['variable'].to_s.upcase

    # @todo add extension to Announcer
    announcer.instance_eval do
      print "$ unset #{variable}" if @options[:env]
    end

    current_value = ENV.delete(variable)

    # if original_env already has the key, then the true original was already recorded from a previous unset or set,
    # so don't record the current value as it will cause ENV not to be restored after the Scenario.
    original_env[variable] = current_value unless original_env.key? variable
  end
end
