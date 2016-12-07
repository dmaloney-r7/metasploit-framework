# frozen_string_literal: true
# -*- coding: binary -*-

#
# Standard Library
#

require 'fileutils'

#
# Project
#

require 'metasploit/framework/version'
require 'rex/compat'

module Msf
  # This class wraps interaction with global configuration that can be used as a
  # persistent storage point for configuration, logs, and other such fun things.
  class Config < Hash
    # The installation's root directory for the distribution
    InstallRoot = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..'))

    # Determines the base configuration directory.
    #
    # @return [String] the base configuration directory
    def self.get_config_root
      # Use MSF_CFGROOT_CONFIG environment variable first.
      val = Rex::Compat.getenv('MSF_CFGROOT_CONFIG')
      return val if val && File.directory?(val)

      # Windows-specific environment variables
      ['HOME', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE'].each do |dir|
        val = Rex::Compat.getenv(dir)
        if val && File.directory?(val)
          return File.join(val, ".msf#{Metasploit::Framework::Version::MAJOR}")
        end
      end

      begin
        # First we try $HOME/.msfx
        File.expand_path("~#{FileSep}.msf#{Metasploit::Framework::Version::MAJOR}")
      rescue ::ArgumentError
        # Give up and install root + ".msfx"
        InstallRoot + ".msf#{Metasploit::Framework::Version::MAJOR}"
      end
    end

    #
    # Default values
    #

    # Default system file separator.
    FileSep     = File::SEPARATOR

    # Default configuration locations.
    Defaults    =
      {
        'ConfigDirectory'     => get_config_root,
        'ConfigFile'          => "config",
        'ModuleDirectory'     => "modules",
        'ScriptDirectory'     => "scripts",
        'LogDirectory'        => "logs",
        'LogosDirectory'      => "logos",
        'SessionLogDirectory' => "logs/sessions",
        'PluginDirectory'     => "plugins",
        'DataDirectory'       => "data",
        'LootDirectory'       => "loot",
        'LocalDirectory'      => "local"
      }.freeze

    ##
    #
    # Class methods
    #
    ##

    # Returns the framework installation root.
    #
    # @return [String] the framework installation root {InstallRoot}.
    def self.install_root
      InstallRoot
    end

    # Returns the configuration directory default.
    #
    # @return [String] the root configuration directory.
    def self.config_directory
      new.config_directory
    end

    # Return the directory that logo files should be loaded from.
    #
    # @return [String] path to the logos directory.
    def self.logos_directory
      new.logos_directory
    end

    # Returns the global module directory.
    #
    # @return [String] path to global module directory.
    def self.module_directory
      new.module_directory
    end

    # Returns the path that scripts can be loaded from.
    #
    # @return [String] path to script directory.
    def self.script_directory
      new.script_directory
    end

    # Returns the directory that log files should be stored in.
    #
    # @return [String] path to log directory.
    def self.log_directory
      new.log_directory
    end

    # Returns the directory that plugins are stored in.
    #
    # @return [String] path to plugin directory.
    def self.plugin_directory
      new.plugin_directory
    end

    # Returns the user-specific plugin base path
    #
    # @return [String] path to user-specific plugin directory.
    def self.user_plugin_directory
      new.user_plugin_directory
    end

    # Returns the directory in which session log files are to reside.
    #
    # @return [String] path to session log directory.
    def self.session_log_directory
      new.session_log_directory
    end

    # Returns the directory in which captured data will reside.
    #
    # @return [String] path to loot directory.
    def self.loot_directory
      new.loot_directory
    end

    # Returns the directory in which locally-generated data will reside.
    #
    # @return [String] path to locally-generated data directory.
    def self.local_directory
      new.local_directory
    end

    # Return the user-specific directory that logo files should be loaded from.
    #
    # @return [String] path to the logos directory.
    def self.user_logos_directory
      new.user_logos_directory
    end

    # Returns the user-specific module base path
    #
    # @return [String] path to user-specific modules directory.
    def self.user_module_directory
      new.user_module_directory
    end

    # Returns the user-specific script base path
    #
    # @return [String] path to user-specific script directory.
    def self.user_script_directory
      new.user_script_directory
    end

    # Returns the data directory
    #
    # @return [String] path to data directory.
    def self.data_directory
      new.data_directory
    end

    # Returns the full path to the configuration file.
    #
    # @return [String] path to the configuration file.
    def self.config_file
      new.config_file
    end

    # Returns the full path to the history file.
    #
    # @return [String] path the history file.
    def self.history_file
      new.history_file
    end

    # Initializes configuration, creating directories as necessary.
    #
    # @return [void]
    def self.init
      new.init
    end

    # Loads configuration from the supplied file path, or the default one if
    # none is specified.
    #
    # @param path [String] the path to the configuration file.
    # @return [Rex::Parser::Ini] INI file parser.
    def self.load(path = nil)
      new.load(path)
    end

    # Saves configuration to the path specified in the ConfigFile hash key or
    # the default path if one isn't specified.  The options should be group
    # references that have named value pairs.
    #
    # @param opts [Hash] Hash containing configuration options.
    # @option opts 'ConfigFile' [Hash] configuration file these options apply
    #   to.
    # @return [void]
    # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
    #   save(
    #     'ExampleGroup' =>
    #        {
    #           'Foo' => 'Cat'
    #        })
    def self.save(opts)
      new.save(opts)
    end

    # Updates the config class' self with the default hash.
    #
    # @return [Hash] the updated Hash.
    def initialize
      update(Defaults)
    end

    # Returns the installation root directory
    #
    # @return [String] the installation root directory {InstallRoot}.
    def install_root
      InstallRoot
    end

    # Return the directory that logo files should be loaded from.
    #
    # @return [String] path to the logos directory.
    def logos_directory
      data_directory + FileSep + self['LogosDirectory']
    end

    # Returns the configuration directory default.
    #
    # @return [String] the root configuration directory.
    def config_directory
      self['ConfigDirectory']
    end

    # Returns the full path to the configuration file.
    #
    # @return [String] path to the configuration file.
    def config_file
      config_directory + FileSep + self['ConfigFile']
    end

    # Returns the full path to the history file.
    #
    # @return [String] path the history file.
    def history_file
      config_directory + FileSep + "history"
    end

    # Returns the global module directory.
    #
    # @return [String] path to global module directory.
    def module_directory
      install_root + FileSep + self['ModuleDirectory']
    end

    # Returns the path that scripts can be loaded from.
    #
    # @return [String] path to script directory.
    def script_directory
      install_root + FileSep + self['ScriptDirectory']
    end

    # Returns the directory that log files should be stored in.
    #
    # @return [String] path to log directory.
    def log_directory
      config_directory + FileSep + self['LogDirectory']
    end

    # Returns the directory that plugins are stored in.
    #
    # @return [String] path to plugin directory.
    def plugin_directory
      install_root + FileSep + self['PluginDirectory']
    end

    # Returns the directory in which session log files are to reside.
    #
    # @return [String] path to session log directory.
    def session_log_directory
      config_directory + FileSep + self['SessionLogDirectory']
    end

    # Returns the directory in which captured data will reside.
    #
    # @return [String] path to loot directory.
    def loot_directory
      config_directory + FileSep + self['LootDirectory']
    end

    # Returns the directory in which locally-generated data will reside.
    #
    # @return [String] path to locally-generated data directory.
    def local_directory
      config_directory + FileSep + self['LocalDirectory']
    end

    # Return the user-specific directory that logo files should be loaded from.
    #
    # @return [String] path to the logos directory.
    def user_logos_directory
      config_directory + FileSep + self['LogosDirectory']
    end

    # Returns the user-specific module base path
    #
    # @return [String] path to user-specific modules directory.
    def user_module_directory
      config_directory + FileSep + "modules"
    end

    # Returns the user-specific plugin base path
    #
    # @return [String] path to user-specific plugin directory.
    def user_plugin_directory
      config_directory + FileSep + "plugins"
    end

    # Returns the user-specific script base path
    #
    # @return [String] path to user-specific script directory.
    def user_script_directory
      config_directory + FileSep + "scripts"
    end

    # Returns the data directory
    #
    # @return [String] path to data directory.
    def data_directory
      install_root + FileSep + self['DataDirectory']
    end

    # Initializes configuration, creating directories as necessary.
    #
    # @return [void]
    def init
      FileUtils.mkdir_p(module_directory)
      FileUtils.mkdir_p(config_directory)
      FileUtils.mkdir_p(log_directory)
      FileUtils.mkdir_p(session_log_directory)
      FileUtils.mkdir_p(loot_directory)
      FileUtils.mkdir_p(local_directory)
      FileUtils.mkdir_p(user_logos_directory)
      FileUtils.mkdir_p(user_module_directory)
      FileUtils.mkdir_p(user_plugin_directory)
    end

    # Loads configuration from the supplied file path, or the default one if
    # none is specified.
    #
    # @param path [String] the path to the configuration file.
    # @return [Rex::Parser::Ini] INI file parser.
    def load(path = nil)
      path = config_file unless path

      Rex::Parser::Ini.new(path)
    end

    # Saves configuration to the path specified in the ConfigFile hash key or
    # the default path if one isn't specified.  The options should be group
    # references that have named value pairs.
    #
    # @param opts [Hash] Hash containing configuration options.
    # @option opts 'ConfigFile' [Hash] configuration file these options apply
    #   to.
    # @return [void]
    # @example Save 'Cat' => 'Foo' in group 'ExampleGroup'
    #   save(
    #     'ExampleGroup' =>
    #        {
    #           'Foo' => 'Cat'
    #        })
    def save(opts)
      ini = Rex::Parser::Ini.new(opts['ConfigFile'] || config_file)

      ini.update(opts)

      ini.to_file
    end
    end
end
