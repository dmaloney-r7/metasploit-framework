# frozen_string_literal: true
require 'anemone/storage/exceptions'

module Anemone
  module Storage
    class Base
      def initialize(adapter)
        @adap = adapter

        # verify adapter conforms to this class's methods
        methods.each do |method|
          unless @adap.respond_to?(method.to_sym)
            raise "Storage adapter must support method #{method}"
          end
        end
      end

      def [](key)
        @adap[key]
      rescue
        puts key
        raise RetrievalError, $ERROR_INFO
      end

      def []=(key, value)
        @adap[key] = value
      rescue
        raise InsertionError, $ERROR_INFO
      end

      def delete(key)
        @adap.delete(key)
      rescue
        raise DeletionError, $ERROR_INFO
      end

      def each
        @adap.each { |k, v| yield k, v }
      rescue
        raise GenericError, $ERROR_INFO
      end

      def merge!(hash)
        @adap.merge!(hash)
      rescue
        raise GenericError, $ERROR_INFO
      end

      def close
        @adap.close
      rescue
        raise CloseError, $ERROR_INFO
      end

      def size
        @adap.size
      rescue
        raise GenericError, $ERROR_INFO
      end

      def keys
        @adap.keys
      rescue
        raise GenericError, $ERROR_INFO
      end

      def has_key?(key)
        @adap.key?(key)
      rescue
        raise GenericError, $ERROR_INFO
      end
    end
  end
end
