# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/io'

module Rex
  module Post
    # make this a module so we can mix it in, and have inheritence like..
    # => [Rex::Post::DispatchNinja::File, Rex::Post::File,
    # Rex::Post::DispatchNinja::IO, Rex::Post::IO, Object, Kernel]

    ###
    #
    # This module simulates the behavior that one would expect from the Ruby File
    # class against a remote entity.  Refer to the ruby documentation for expected
    # behavior.
    #
    ###
    module File
      protected

        # inherits fd and mode from IO
        attr_accessor :filename

      public

        # f = File.new("testfile", "r")
        # f = File.new("newfile",  "w+")
        # f = File.new("newfile", File::CREAT|File::TRUNC|File::RDWR, 0644)
        # !!! I suppose I should figure out the correct default for perm..
        def initialize(name, mode = 'r', perm = 0)
        end

        def path
          filename
        end

        # ctime/atime blah need fstat..
        # need lchown/chown/fchown, etc, etc

        # proxy these methods
        def self.basename(*a)
          ::File.basename(*a)
        end

        def self.dirname(*a)
          ::File.dirname(*a)
        end

        def self.extname(*a)
          ::File.extname(*a)
        end

        # !!! we might actually want to handle this File::SEPERATOR stuff
        # for win32 support, etc.
        def self.join(*a)
          ::File.join(*a)
        end

        def self.chmod
          raise NotImplementedError
        end

        def self.chown
          raise NotImplementedError
        end

        def self.delete(*a)
          unlink(*a)
        end

        def self.unlink
          raise NotImplementedError
        end

        def self.lchmod
          raise NotImplementedError
        end

        def self.lchown
          raise NotImplementedError
        end

        def self.link
          raise NotImplementedError
        end

        def self.lstat
          raise NotImplementedError
        end

        # this, along with all the other globbing/search stuff, probably
        # won't get implemented, atleast for a bit...
        def self.expand_path
          raise NotImplementedError
        end

        def self.fnmatch(*a)
          fnmatch?(*a)
        end

        def self.fnmatch?
          raise NotImplementedError
        end

        #
        # autogen'd stat passthroughs
        #
        def self.atime(name)
          stat(name).atime
        end

        def self.blockdev?(name)
          stat(name).blockdev?
        end

        def self.chardev?(name)
          stat(name).chardev?
        end

        def self.ctime(name)
          stat(name).ctime
        end

        def self.directory?(name)
          stat(name).directory?
        end

        def self.executable?(name)
          stat(name).executable?
        end

        def self.executable_real?(name)
          stat(name).executable_real?
        end

        def self.file?(name)
          stat(name).file?
        end

        def self.ftype(name)
          stat(name).ftype
        end

        def self.grpowned?(name)
          stat(name).grpowned?
        end

        def self.mtime(name)
          stat(name).mtime
        end

        def self.owned?(name)
          stat(name).owned?
        end

        def self.pipe?(name)
          stat(name).pipe?
        end

        def self.readable?(name)
          stat(name).readable?
        end

        def self.readable_real?(name)
          stat(name).readable_real?
        end

        def self.setuid?(name)
          stat(name).setuid?
        end

        def self.setgid?(name)
          stat(name).setgid?
        end

        def self.size(name)
          stat(name).size
        end

        def self.socket?(name)
          stat(name).socket?
        end

        def self.sticky?(name)
          stat(name).sticky?
        end

        def self.symlink?(name)
          stat(name).symlink?
        end

        def self.writeable?(name)
          stat(name).writeable?
        end

        def self.writeable_real?(name)
          stat(name).writeable_real?
        end

        def self.zero?(name)
          stat(name).zero?
        end
    end
  end; end # Post/Rex
