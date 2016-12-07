# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Post
    ###
    #
    # This class wraps the behavior of the Ruby Dir class against a remote entity.
    # Refer to the Ruby documentation for expected behavior.
    #
    ###
    class Dir
      def self.entries(_name)
        raise NotImplementedError
    end

      def self.foreach(name, &block)
        entries(name).each(&block)
      end

      def self.chdir(_path)
        raise NotImplementedError
      end

      def self.mkdir(_path)
        raise NotImplementedError
      end

      def self.pwd
        raise NotImplementedError
      end

      def self.getwd
        raise NotImplementedError
      end

      def self.delete(_path)
        raise NotImplementedError
      end

      def self.rmdir(_path)
        raise NotImplementedError
      end

      def self.unlink(_path)
        raise NotImplementedError
      end
    end
    end; end # Post/Rex
