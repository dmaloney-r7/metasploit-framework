# frozen_string_literal: true
# -*- coding: binary -*-

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/channels/pools/stream_pool'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/image'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/io'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/memory'
require 'rex/post/meterpreter/extensions/stdapi/sys/process_subsystem/thread'

module Rex
  module Post
    module Meterpreter
      module Extensions
        module Stdapi
          module Sys
            ##
            #
            # This class implements the Rex::Post::Process interface.
            #
            ##
            class Process < Rex::Post::Process
              include Rex::Post::Meterpreter::ObjectAliasesContainer

              ##
              #
              # Class methods
              #
              ##

              class << self
                attr_accessor :client
              end

              #
              # Returns the process identifier of the process supplied in key if it's
              # valid.
              #
              def self.[](key)
                each_process do |p|
                  return p['pid'] if p['name'].casecmp(key.downcase).zero?
                end

                nil
              end

              #
              # Attachs to the supplied process with a given set of permissions.
              #
              def self.open(pid = nil, perms = nil)
                real_perms = 0

                perms = PROCESS_ALL if perms.nil?

                if perms & PROCESS_READ
                  real_perms |= PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
                end

                if perms & PROCESS_WRITE
                  real_perms |= PROCESS_SET_SESSIONID | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
                end

                if perms & PROCESS_EXECUTE
                  real_perms |= PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS | PROCESS_SUSPEND_RESUME
                end

                _open(pid, real_perms)
              end

              #
              # Low-level process open.
              #
              def self._open(pid, perms, inherit = false)
                request = Packet.create_request('stdapi_sys_process_attach')

                pid = 0 if pid.nil?

                # Populate the request
                request.add_tlv(TLV_TYPE_PID, pid)
                request.add_tlv(TLV_TYPE_PROCESS_PERMS, perms)
                request.add_tlv(TLV_TYPE_INHERIT, inherit)

                # Transmit the request
                response = client.send_request(request)
                handle   = response.get_tlv_value(TLV_TYPE_HANDLE)

                # If the handle is valid, allocate a process instance and return it
                return new(pid, handle) unless handle.nil?

                nil
              end

              #
              # Executes an application using the arguments provided
              #
              # Hash arguments supported:
              #
              #   Hidden      => true/false
              #   Channelized => true/false
              #   Suspended   => true/false
              #   InMemory    => true/false
              #
              def self.execute(path, arguments = nil, opts = nil)
                request = Packet.create_request('stdapi_sys_process_execute')
                flags   = 0

                # If we were supplied optional arguments...
                unless opts.nil?
                  flags |= PROCESS_EXECUTE_FLAG_HIDDEN if opts['Hidden']
                  flags |= PROCESS_EXECUTE_FLAG_CHANNELIZED if opts['Channelized']
                  flags |= PROCESS_EXECUTE_FLAG_SUSPENDED if opts['Suspended']
                  flags |= PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN if opts['UseThreadToken']
                  flags |= PROCESS_EXECUTE_FLAG_DESKTOP if opts['Desktop']
                  if opts['Session']
                    flags |= PROCESS_EXECUTE_FLAG_SESSION
                    request.add_tlv(TLV_TYPE_PROCESS_SESSION, opts['Session'])
                  end
                  inmem = opts['InMemory']
                  if inmem

                    # add the file contents into the tlv
                    f = ::File.new(path, 'rb')
                    request.add_tlv(TLV_TYPE_VALUE_DATA, f.read(f.stat.size))
                    f.close

                    # replace the path with the "dummy"
                    path = inmem.is_a?(String) ? inmem : 'cmd'
                  end
                end

                request.add_tlv(TLV_TYPE_PROCESS_PATH, client.unicode_filter_decode(path))

                # If process arguments were supplied
                request.add_tlv(TLV_TYPE_PROCESS_ARGUMENTS, arguments) unless arguments.nil?

                request.add_tlv(TLV_TYPE_PROCESS_FLAGS, flags)

                response = client.send_request(request)

                # Get the response parameters
                pid        = response.get_tlv_value(TLV_TYPE_PID)
                handle     = response.get_tlv_value(TLV_TYPE_PROCESS_HANDLE)
                channel_id = response.get_tlv_value(TLV_TYPE_CHANNEL_ID)
                channel    = nil

                # If we were creating a channel out of this
                unless channel_id.nil?
                  channel = Rex::Post::Meterpreter::Channels::Pools::StreamPool.new(client,
                                                                                    channel_id, "stdapi_process", CHANNEL_FLAG_SYNCHRONOUS)
                end

                # Return a process instance
                new(pid, handle, channel)
              end

              #
              # Kills one or more processes.
              #
              def self.kill(*args)
                request = Packet.create_request('stdapi_sys_process_kill')

                args.each do |id|
                  request.add_tlv(TLV_TYPE_PID, id)
                end

                client.send_request(request)

                true
              end

              #
              # Gets the process id that the remote side is executing under.
              #
              def self.getpid
                request = Packet.create_request('stdapi_sys_process_getpid')

                response = client.send_request(request)

                response.get_tlv_value(TLV_TYPE_PID)
              end

              #
              # Enumerates all of the elements in the array returned by get_processes.
              #
              def self.each_process(&block)
                get_processes.each(&block)
              end

              #
              # Returns a ProcessList of processes as Hash objects with keys for 'pid',
              # 'ppid', 'name', 'path', 'user', 'session' and 'arch'.
              #
              def self.get_processes
                request   = Packet.create_request('stdapi_sys_process_get_processes')
                processes = ProcessList.new

                response = client.send_request(request)

                response.each(TLV_TYPE_PROCESS_GROUP) do |p|
                  arch = ""

                  pa = p.get_tlv_value(TLV_TYPE_PROCESS_ARCH)
                  if !pa.nil?
                    if pa == 1 # PROCESS_ARCH_X86
                      arch = ARCH_X86
                    elsif pa == 2 # PROCESS_ARCH_X64
                      arch = ARCH_X64
                    end
                  else
                    arch = p.get_tlv_value(TLV_TYPE_PROCESS_ARCH_NAME)
                  end

                  processes <<
                    {
                      'pid'      => p.get_tlv_value(TLV_TYPE_PID),
                      'ppid'     => p.get_tlv_value(TLV_TYPE_PARENT_PID),
                      'name'     => client.unicode_filter_encode(p.get_tlv_value(TLV_TYPE_PROCESS_NAME)),
                      'path'     => client.unicode_filter_encode(p.get_tlv_value(TLV_TYPE_PROCESS_PATH)),
                      'session'  => p.get_tlv_value(TLV_TYPE_PROCESS_SESSION),
                      'user'     => client.unicode_filter_encode(p.get_tlv_value(TLV_TYPE_USER_NAME)),
                      'arch'     => arch
                    }
                end

                processes
              end

              #
              # An alias for get_processes.
              #
              def self.processes
                get_processes
              end

              ##
              #
              # Instance methods
              #
              ##

              #
              # Initializes the process instance and its aliases.
              #
              def initialize(pid, handle, channel = nil)
                self.client  = self.class.client
                self.handle  = handle
                self.channel = channel

                # If the process identifier is zero, then we must lookup the current
                # process identifier
                self.pid = if pid == 0
                             client.sys.process.getpid
                           else
                             pid
                           end

                initialize_aliases(
                  'image' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Image.new(self),
                  'io'     => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::IO.new(self),
                  'memory' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Memory.new(self),
                  'thread' => Rex::Post::Meterpreter::Extensions::Stdapi::Sys::ProcessSubsystem::Thread.new(self)
                )

                # Ensure the remote object is closed when all references are removed
                ObjectSpace.define_finalizer(self, self.class.finalize(client, handle))
              end

              def self.finalize(client, handle)
                proc { close(client, handle) }
              end

              #
              # Returns the executable name of the process.
              #
              def name
                get_info['name']
              end

              #
              # Returns the path to the process' executable.
              #
              def path
                get_info['path']
              end

              #
              # Closes the handle to the process that was opened.
              #
              def self.close(client, handle)
                request = Packet.create_request('stdapi_sys_process_close')
                request.add_tlv(TLV_TYPE_HANDLE, handle)
                response = client.send_request(request, nil)
                handle = nil
                true
              end

              #
              # Instance method
              #
              def close(handle = self.handle)
                unless pid.nil?
                  ObjectSpace.undefine_finalizer(self)
                  self.class.close(client, handle)
                  self.pid = nil
                end
              end

              #
              # Block until this process terminates on the remote side.
              # By default we choose not to allow a packet responce timeout to
              # occur as we may be waiting indefinatly for the process to terminate.
              #
              def wait(timeout = -1)
                request = Packet.create_request('stdapi_sys_process_wait')

                request.add_tlv(TLV_TYPE_HANDLE, handle)

                response = client.send_request(request, timeout)

                self.handle = nil

                true
              end

              attr_reader :client, :handle, :channel, :pid # :nodoc:

              protected

              attr_writer :client, :handle, :channel, :pid # :nodoc:

              #
              # Gathers information about the process and returns a hash.
              #
              def get_info
                request = Packet.create_request('stdapi_sys_process_get_info')
                info    = {}

                request.add_tlv(TLV_TYPE_HANDLE, handle)

                # Send the request
                response = client.send_request(request)

                # Populate the hash
                info['name'] = client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_PROCESS_NAME))
                info['path'] = client.unicode_filter_encode(response.get_tlv_value(TLV_TYPE_PROCESS_PATH))

                info
              end
            end

            #
            # Simple wrapper class for storing processes
            #
            class ProcessList < Array
              #
              # Create a Rex::Text::Table out of the processes stored in this list
              #
              # +opts+ is passed on to Rex::Text::Table.new, mostly unmolested
              #
              # Note that this output is affected by Rex::Post::Meterpreter::Client#unicode_filter_encode
              #
              def to_table(opts = {})
                return Rex::Text::Table.new(opts) if empty?

                cols = [ "PID", "PPID", "Name", "Arch", "Session", "User", "Path" ]
                # Arch and Session are specific to native Windows, PHP and Java can't do
                # ppid.  Cut columns from the list if they aren't there.  It is conceivable
                # that processes might have different columns, but for now assume that the
                # first one is representative.
                cols.delete_if { |c| !first.key?(c.downcase) || first[c.downcase].nil? }

                opts = {
                  'Header' => 'Process List',
                  'Indent' => 1,
                  'Columns' => cols
                }.merge(opts)

                tbl = Rex::Text::Table.new(opts)
                each do |process|
                  tbl << cols.map do |c|
                    col = c.downcase
                    val = process[col]
                    if col == 'session'
                      val == 0xFFFFFFFF ? '' : val.to_s
                    else
                      val
                    end
                  end.compact
                end

                tbl
              end
            end
          end; end; end; end; end; end
