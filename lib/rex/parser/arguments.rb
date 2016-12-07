# frozen_string_literal: true
# -*- coding: binary -*-
require 'shellwords'

module Rex
  module Parser
    ###
    #
    # This class parses arguments in a getopt style format, kind of.
    # Unfortunately, the default ruby getopt implementation will only
    # work on ARGV, so we can't use it.
    #
    ###
    class Arguments
      #
      # Specifies that an option is expected to have an argument
      #
      HasArgument = (1 << 0)

      #
      # Initializes the format list with an array of formats like:
      #
      # Arguments.new(
      #    '-b' => [ false, "some text" ]
      # )
      #
      def initialize(fmt)
        self.fmt = fmt
        # I think reduce is a better name for this method, but it doesn't exist
        # before 1.8.7, so use the stupid inject instead.
        self.longest = fmt.keys.inject(0) { |max, str|
          max = (max > str.length ? max : str.length)
        }
      end

      #
      # Takes a string and converts it into an array of arguments.
      #
      def self.from_s(str)
        Shellwords.shellwords(str)
      end

      #
      # Parses the supplied arguments into a set of options.
      #
      def parse(args)
        skip_next = false

        args.each_with_index do |arg, idx|
          if skip_next == true
            skip_next = false
            next
          end

          if arg =~ /^-/
            cfs = arg[0..2]

            fmt.each_pair do |fmtspec, val|
              next if fmtspec != cfs

              param = nil

              if val[0]
                param = args[idx + 1]
                skip_next = true
              end

              yield fmtspec, idx, param
            end
          else
            yield nil, idx, arg
          end
        end
      end

      #
      # Returns usage information for this parsing context.
      #
      def usage
        txt = "\nOPTIONS:\n\n"

        fmt.sort.each do |entry|
          fmtspec, val = entry

          txt << "    #{fmtspec.ljust(longest)}" + (val[0] == true ? " <opt>  " : "        ")
          txt << val[1] + "\n"
        end

        txt << "\n"

        txt
      end

      def include?(search)
        fmt.include?(search)
      end

      def arg_required?(opt)
        fmt[opt][0] if fmt[opt]
      end

      attr_accessor :fmt     # :nodoc:
      attr_accessor :longest # :nodoc:
    end
  end
end
