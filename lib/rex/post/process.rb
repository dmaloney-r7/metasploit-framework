# frozen_string_literal: true
# -*- coding: binary -*-

module Rex
  module Post
    ###
    #
    # This class performs basic process operations against a process running on a
    # remote machine via the post-exploitation mechanisms.  Refer to the Ruby
    # documentation for expected behaviors.
    #
    ###
    class Process
      def self.getresuid
        raise NotImplementedError
      end

      def self.setresuid(_a, _b, _c)
        raise NotImplementedError
      end

      def self.euid
        getresuid[1]
      end

      def self.euid=(id)
        setresuid(-1, id, -1)
      end

      def self.uid
        getresuid[0]
      end

      def self.uid=(id)
        setresuid(id, -1, -1)
      end

      def self.egid
        getresgid[1]
      end

      def self.egid=(id)
        setresgid(-1, id, -1)
      end

      def self.gid
        getresgid[0]
      end

      def self.gid=(id)
        setresgid(id, -1, -1)
      end

      def self.pid
        raise NotImplementedError
      end

      def self.ppid
        raise NotImplementedError
      end
    end
  end; end # Post/Rex
