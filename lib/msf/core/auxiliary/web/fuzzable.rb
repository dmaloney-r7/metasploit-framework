# frozen_string_literal: true
# -*- coding: binary -*-
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/

require 'net/https'
require 'net/http'
require 'uri'

module Msf
  module Auxiliary::Web
    class Fuzzable
      # load and include all available analysis/audit techniques
      lib = File.dirname(__FILE__) + '/analysis/*.rb'
      Dir.glob(lib).each { |f| require f }
      Analysis.constants.each { |technique| include Analysis.const_get(technique) }

      attr_accessor :fuzzer

      def fuzzed?(opts = {})
        fuzzer.checked? fuzz_id(opts)
      end

      def fuzzed(opts = {})
        fuzzer.checked fuzz_id(opts)
      end

      def fuzz_id(opts = {})
        "#{opts[:type]}:#{fuzzer.shortname}:#{method}:#{action}:#{params.keys.sort}:#{altered}=#{altered_value}"
      end

      def fuzz(cfuzzer = nil)
        fuzz_wrapper(cfuzzer) { |p| yield(p.submit, p) }
      end

      def fuzz_async(cfuzzer = nil)
        fuzz_wrapper(cfuzzer) { |p| p.submit_async { |res| yield(res, p) } }
      end

      def submit(opts = {})
        fuzzer&.increment_request_counter

        http.request(*request(opts))
      end

      def submit_async(opts = {}, &callback)
        fuzzer.increment_request_counter

        http.request_async(*request(opts)) do |resp|
          yield resp if callback
        end

        nil
      end

      def http
        fuzzer.http
      end

      def hash
        to_hash.hash
      end

      def ==(other)
        hash == other.hash
      end

      def dup
        cf = fuzzer
        self.fuzzer = nil
        ce = Marshal.load(Marshal.dump(self))
        self.fuzzer = ce.fuzzer = cf
        ce
      end

      private

      def fuzz_wrapper(cfuzzer = nil)
        self.fuzzer ||= cfuzzer
        permutations.each do |p|
          yield p
        end
      end
    end
    end
end
