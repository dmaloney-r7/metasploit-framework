# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  module Parser
    ###
    #
    # This class parses the contents of an INI file.
    #
    ###
    class Ini < Hash
      ##
      #
      # Factories
      #
      ##

      #
      # Creates a new class instance and reads in the contents of the supplied
      # file path.
      #
      def self.from_file(path)
        ini = Ini.new(path)
        ini.from_file
        ini
      end

      #
      # Creates a new class instance from the supplied string.
      #
      def self.from_s(str)
        ini = Ini.new
        ini.from_s(str)
        ini
      end

      #
      # Initializes an ini instance and tries to read in the groups from the
      # file if it exists.
      #
      def initialize(path = nil)
        self.path = path

        # Try to synchronize ourself with the file if we
        # have one
        begin
          from_file if self.path
        rescue
        end
      end

      alias each_group each_key

      #
      # Adds a group of the supplied name if it doesn't already exist.
      #
      def add_group(name = 'global', reset = true)
        self[name] = {} if reset == true
        self[name] = {} unless self[name]

        self[name]
      end

      #
      # Checks to see if name is a valid group.
      #
      def group?(name)
        !self[name].nil?
      end

      ##
      #
      # Serializers
      #
      ##

      #
      # Reads in the groups from the supplied file path or the instance's file
      # path.
      #
      def from_file(fpath = nil)
        fpath = path unless fpath

        read_groups(fpath)
      end

      #
      # Reads in the groups from the supplied string.
      #
      def from_s(str)
        read_groups_string(str.split("\n"))
      end

      #
      # Writes the group settings to a file.
      #
      def to_file(tpath = nil)
        tpath = path unless tpath

        f = File.new(tpath, "w")
        f.write(to_s)
        f.close
      end

      #
      # Converts the groups to a string.
      #
      def to_s
        str = ''
        keys.sort.each do |k|
          str << "[#{k}]\n"

          self[k].each_pair do |var, val|
            str << "#{var}=#{val}\n"
          end

          str << "\n"
        end

        str
      end

      attr_reader :path

      protected

      #
      # Reads in the groups and their attributes from the supplied file
      # path or from the instance's file path if one was set.
      #
      def read_groups(fpath) # :nodoc:
        unless fpath
          raise ArgumentError, "No file path specified.",
                caller
        end

        # Read in the contents of the file
        lines = ::IO.readlines(fpath)

        # Now read the contents from the supplied string
        read_groups_string(lines)
      end

      #
      # Reads groups from the supplied string
      #
      def read_groups_string(str) # :nodoc:
        # Reset the groups hash
        clear

        # The active group
        active_group = nil

        # Walk each line initializing the groups
        str.each do |line|
          next if line =~ /^;/

          # Eliminate cr/lf
          line.gsub!(/(\n|\r)/, '')

          # Is it a group [bob]?
          if (md = line.match(/^\[(.+?)\]/))
            active_group = md[1]
            self[md[1]]  = {}
          # Is it a VAR=VAL?
          elsif (md = line.match(/^(.+?)=(.*)$/))
            if active_group
              var = md[1]
              val = md[2]

              # don't clobber datastore nils with ""
              self[active_group][var] = val unless val.empty?
            end
          end
        end
      end

      attr_writer :path # :nodoc:
    end
  end
end
