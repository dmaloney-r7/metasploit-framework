# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/dir'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Fs
            ###
            #
            # This class implements directory operations against the remote endpoint.  It
            # implements the Rex::Post::Dir interface.
            #
            ###
            class Dir < Rex::Post::Dir
              class << self
                attr_accessor :client
              end

              ##
              #
              # Constructor
              #
              ##

              #
              # Initializes the directory instance.
              #
              def initialize(path)
                self.path   = path
                self.client = self.class.client
              end

              ##
              #
              # Enumeration
              #
              ##

              #
              # Enumerates all of the contents of the directory.
              #
              def each(&block)
                client.fs.dir.foreach(path, &block)
              end

              #
              # Enumerates all of the files/folders in a given directory.
              #
              def self.entries(name = getwd, glob = nil)
                request = Packet.create_request('stdapi_fs_ls')
                files   = []
                name = name + ::File::SEPARATOR + glob if glob

                request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

                response = client.send_request(request)

                response.each(TLV_TYPE_FILE_NAME) do |file_name|
                  files << client.unicode_filter_encode(file_name.value)
                end

                files
              end

              #
              # Enumerates files with a bit more information than the default entries.
              #
              def self.entries_with_info(name = getwd)
                request = Packet.create_request('stdapi_fs_ls')
                files   = []

                request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(name))

                response = client.send_request(request)

                fname = response.get_tlvs(TLV_TYPE_FILE_NAME)
                fsname = response.get_tlvs(TLV_TYPE_FILE_SHORT_NAME)
                fpath = response.get_tlvs(TLV_TYPE_FILE_PATH)
                sbuf  = response.get_tlvs(TLV_TYPE_STAT_BUF)

                return [] if !fname || !sbuf

                fname.each_with_index do |file_name, idx|
                  st = nil

                  if sbuf[idx]
                    st = ::Rex::Post::FileStat.new
                    st.update(sbuf[idx].value)
                  end

                  files <<
                    {
                      'FileName' => client.unicode_filter_encode(file_name.value),
                      'FilePath' => client.unicode_filter_encode(fpath[idx].value),
                      'FileShortName' => fsname[idx] ? fsname[idx].value : nil,
                      'StatBuf' => st
                    }
                end

                files
              end

              ##
              #
              # General directory operations
              #
              ##

              #
              # Changes the working directory of the remote process.
              #
              def self.chdir(path)
                request = Packet.create_request('stdapi_fs_chdir')

                request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(path))

                response = client.send_request(request)

                0
              end

              #
              # Creates a directory.
              #
              def self.mkdir(path)
                request = Packet.create_request('stdapi_fs_mkdir')

                request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(path))

                response = client.send_request(request)

                0
              end

              #
              # Returns the current working directory of the remote process.
              #
              def self.pwd
                request = Packet.create_request('stdapi_fs_getwd')

                response = client.send_request(request)

                client.unicode_filter_encode(response.get_tlv(TLV_TYPE_DIRECTORY_PATH).value)
              end

              #
              # Synonym for pwd.
              #
              def self.getwd
                pwd
              end

              #
              # Removes the supplied directory if it's empty.
              #
              def self.delete(path)
                request = Packet.create_request('stdapi_fs_delete_dir')

                request.add_tlv(TLV_TYPE_DIRECTORY_PATH, client.unicode_filter_decode(path))

                response = client.send_request(request)

                0
              end

              #
              # Synonyms for delete.
              #
              def self.rmdir(path)
                delete(path)
              end

              #
              # Synonyms for delete.
              #
              def self.unlink(path)
                delete(path)
              end

              ##
              #
              # Directory mirroring
              #
              ##

              #
              # Downloads the contents of a remote directory a
              # local directory, optionally in a recursive fashion.
              #
              def self.download(dst, src, opts, force = true, glob = nil, &stat)
                recursive = false
                continue = false
                tries = false
                tries_no = 0
                tries_cnt = 0
                if opts
                  timestamp = opts["timestamp"]
                  recursive = true if opts["recursive"]
                  continue = true if opts["continue"]
                  tries = true if opts["tries"]
                  tries_no = opts["tries_no"]
                end
                begin
                  dir_files = entries(src, glob)
                rescue Rex::TimeoutError
                  if tries && (tries_no == 0 || tries_cnt < tries_no)
                    tries_cnt += 1
                    stat&.call('error listing  - retry #', tries_cnt, src)
                    retry
                  else
                    stat&.call('error listing directory - giving up', src, dst)
                    raise
                  end
                end

                dir_files.each do |src_sub|
                  dst_item = dst + ::File::SEPARATOR + client.unicode_filter_encode(src_sub)
                  src_item = src + client.fs.file.separator + client.unicode_filter_encode(src_sub)

                  next if (src_sub == '.') || (src_sub == '..')

                  tries_cnt = 0
                  begin
                    src_stat = client.fs.filestat.new(src_item)
                  rescue Rex::TimeoutError
                    if tries && (tries_no == 0 || tries_cnt < tries_no)
                      tries_cnt += 1
                      stat&.call('error opening file - retry #', tries_cnt, src_item)
                      retry
                    else
                      stat&.call('error opening file - giving up', tries_cnt, src_item)
                      raise
                    end
                  end

                  if src_stat.file?
                    dst_item << timestamp if timestamp

                    stat&.call('downloading', src_item, dst_item)

                    begin
                      result = if continue || tries # allow to file.download to log messages
                                 client.fs.file.download_file(dst_item, src_item, opts, &stat)
                               else
                                 client.fs.file.download_file(dst_item, src_item, opts)
                               end
                      stat&.call(result, src_item, dst_item)
                    rescue ::Rex::Post::Meterpreter::RequestError => e
                      if force
                        stat&.call('failed', src_item, dst_item)
                      else
                        raise e
                      end
                    end

                  elsif src_stat.directory?
                    next if recursive == false

                    begin
                      ::Dir.mkdir(dst_item)
                    rescue
                    end

                    stat&.call('mirroring', src_item, dst_item)
                    download(dst_item, src_item, opts, force, glob, &stat)
                    stat&.call('mirrored', src_item, dst_item)
                  end
                end # entries
              end

              #
              # Uploads the contents of a local directory to a remote
              # directory, optionally in a recursive fashion.
              #
              def self.upload(dst, src, recursive = false, &stat)
                ::Dir.entries(src).each do |src_sub|
                  dst_item = dst + client.fs.file.separator + client.unicode_filter_encode(src_sub)
                  src_item = src + ::File::SEPARATOR + client.unicode_filter_encode(src_sub)

                  next if (src_sub == '.') || (src_sub == '..')

                  src_stat = ::File.stat(src_item)

                  if src_stat.file?
                    stat&.call('uploading', src_item, dst_item)
                    client.fs.file.upload(dst_item, src_item)
                    stat&.call('uploaded', src_item, dst_item)
                  elsif src_stat.directory?
                    next if recursive == false

                    begin
                      mkdir(dst_item)
                    rescue
                    end

                    stat&.call('mirroring', src_item, dst_item)
                    upload(dst_item, src_item, recursive, &stat)
                    stat&.call('mirrored', src_item, dst_item)
                  end
                end
              end

              #
              # The path of the directory that was opened.
              #
              attr_reader :path

              protected

              attr_accessor :client # :nodoc:
              attr_writer   :path # :nodoc:
            end
          end; end; end; end; end; end
