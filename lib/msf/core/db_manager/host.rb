# frozen_string_literal: true
module Msf::DBManager::Host
  # Deletes a host and associated data matching this address/comm
  def del_host(wspace, address, comm = '')
    ::ActiveRecord::Base.connection_pool.with_connection do
      address, scope = address.split('%', 2)
      host = wspace.hosts.find_by_address_and_comm(address, comm)
      host&.destroy
    end
  end

  #
  # Iterates over the hosts table calling the supplied block with the host
  # instance of each entry.
  #
  def each_host(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.hosts.each do |host|
        yield(host)
      end
    end
  end

  # Exactly like report_host but waits for the database to create a host and returns it.
  def find_or_create_host(opts)
    report_host(opts)
  end

  #
  # Find a host.  Performs no database writes.
  #
  def get_host(opts)
    if opts.is_a? ::Mdm::Host
      return opts
    elsif opts.is_a? String
      raise "This invokation of get_host is no longer supported: #{caller}"
    else
      address = opts[:addr] || opts[:address] || opts[:host] || return
      return address if address.is_a? ::Mdm::Host
    end
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      wspace = find_workspace(wspace) if wspace.is_a? String

      address = normalize_host(address)
      return wspace.hosts.find_by_address(address)
    end
  end

  # Look for an address across all comms
  def has_host?(wspace, addr)
    ::ActiveRecord::Base.connection_pool.with_connection do
      address, scope = addr.split('%', 2)
      wspace.hosts.find_by_address(addr)
    end
  end

  # Returns a list of all hosts in the database
  def hosts(wspace = workspace, only_up = false, addresses = nil)
    ::ActiveRecord::Base.connection_pool.with_connection do
      conditions = {}
      conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if only_up
      conditions[:address] = addresses if addresses
      wspace.hosts.where(conditions).order(:address)
    end
  end

  #
  # Returns something suitable for the +:host+ parameter to the various report_* methods
  #
  # Takes a Host object, a Session object, an Msf::Session object or a String
  # address
  #
  def normalize_host(host)
    return host if defined?(::Mdm) && host.is_a?(::Mdm::Host)
    norm_host = nil

    if host.is_a? String

      if Rex::Socket.is_ipv4?(host)
        # If it's an IPv4 addr with a port on the end, strip the port
        norm_host = if host =~ /((\d{1,3}\.){3}\d{1,3}):\d+/
                      Regexp.last_match(1)
                    else
                      host
                    end
      elsif Rex::Socket.is_ipv6?(host)
        # If it's an IPv6 addr, drop the scope
        address, scope = host.split('%', 2)
        norm_host = address
      else
        norm_host = Rex::Socket.getaddress(host, true)
      end
    elsif defined?(::Mdm) && host.is_a?(::Mdm::Session)
      norm_host = host.host
    elsif host.respond_to?(:session_host)
      # Then it's an Msf::Session object
      norm_host = host.session_host
    end

    # If we got here and don't have a norm_host yet, it could be a
    # Msf::Session object with an empty or nil tunnel_host and tunnel_peer;
    # see if it has a socket and use its peerhost if so.
    if
        norm_host.nil? &&
        host.respond_to?(:sock) &&
        host.sock.respond_to?(:peerhost) &&
        !host.sock.peerhost.to_s.empty?

      norm_host = session.sock.peerhost
    end
    # If We got here and still don't have a real host, there's nothing left
    # to try, just log it and return what we were given
    unless norm_host
      dlog("Host could not be normalized: #{host.inspect}")
      norm_host = host
    end

    norm_host
  end

  #
  # Report a host's attributes such as operating system and service pack
  #
  # The opts parameter MUST contain
  # +:host+::         -- the host's ip address
  #
  # The opts parameter can contain:
  # +:state+::        -- one of the Msf::HostState constants
  # +:os_name+::      -- something like "Windows", "Linux", or "Mac OS X"
  # +:os_flavor+::    -- something like "Enterprise", "Pro", or "Home"
  # +:os_sp+::        -- something like "SP2"
  # +:os_lang+::      -- something like "English", "French", or "en-US"
  # +:arch+::         -- one of the ARCH_* constants
  # +:mac+::          -- the host's MAC address
  # +:scope+::        -- interface identifier for link-local IPv6
  # +:virtual_host+:: -- the name of the VM host software, eg "VMWare", "QEMU", "Xen", etc.
  #
  def report_host(opts)
    return unless active
    addr = opts.delete(:host) || return

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    return if addr.eql? "Remote Pipe"

    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      wspace = find_workspace(wspace) if wspace.is_a? String

      ret = {}

      if !addr.is_a? ::Mdm::Host
        addr = normalize_host(addr)

        unless ipv46_validator(addr)
          raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
        end

        host = if opts[:comm] && !opts[:comm].empty?
                 wspace.hosts.where(address: addr, comm: opts[:comm]).first_or_initialize
               else
                 wspace.hosts.where(address: addr).first_or_initialize
               end
      else
        host = addr
      end

      # Truncate the info field at the maximum field length
      opts[:info] = opts[:info][0, 65535] if opts[:info]

      # Truncate the name field at the maximum field length
      opts[:name] = opts[:name][0, 255] if opts[:name]

      opts.each do |k, v|
        if host.attribute_names.include?(k.to_s)
          unless host.attribute_locked?(k.to_s)
            host[k] = v.to_s.gsub(/[\x00-\x1f]/n, '')
          end
        else
          dlog("Unknown attribute for ::Mdm::Host: #{k}")
        end
      end
      host.info = host.info[0, ::Mdm::Host.columns_hash["info"].limit] if host.info

      # Set default fields if needed
      host.state       = Msf::HostState::Alive unless host.state
      host.comm        = ''        unless host.comm
      host.workspace   = wspace    unless host.workspace

      if host.changed?
        msf_import_timestamps(opts, host)
        host.save!
      end

      if opts[:task]
        Mdm::TaskHost.create(
          task: opts[:task],
          host: host
        )
      end

      host
    end
  end

  #
  # Update a host's attributes via semi-standardized sysinfo hash (Meterpreter)
  #
  # The opts parameter MUST contain the following entries
  # +:host+::           -- the host's ip address
  # +:info+::           -- the information hash
  # * 'Computer'        -- the host name
  # * 'OS'              -- the operating system string
  # * 'Architecture'    -- the hardware architecture
  # * 'System Language' -- the system language
  #
  # The opts parameter can contain:
  # +:workspace+::      -- the workspace for this host
  #
  def update_host_via_sysinfo(opts)
    return unless active
    addr = opts.delete(:host) || return
    info = opts.delete(:info) || return

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    return if addr.eql? "Remote Pipe"

    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      wspace = find_workspace(wspace) if wspace.is_a? String

      if !addr.is_a? ::Mdm::Host
        addr = normalize_host(addr)
        addr, scope = addr.split('%', 2)
        opts[:scope] = scope if scope

        unless ipv46_validator(addr)
          raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
        end

        host = if opts[:comm] && !opts[:comm].empty?
                 wspace.hosts.where(address: addr, comm: opts[:comm]).first_or_initialize
               else
                 wspace.hosts.where(address: addr).first_or_initialize
               end
      else
        host = addr
      end

      res = {}

      res[:name] = info['Computer'] if info['Computer']

      res[:arch] = info['Architecture'].split(/\s+/).first if info['Architecture']

      if info['OS'] =~ /^Windows\s*([^\(]+)\(([^\)]+)\)/i
        res[:os_name] = "Windows #{Regexp.last_match(1).strip}"
        build = Regexp.last_match(2).strip

        res[:os_sp] = "SP" + Regexp.last_match(1) if build =~ /Service Pack (\d+)/
      end

      if info["System Language"]
        case info["System Language"]
        when /^en_/
          res[:os_lang] = "English"
        end
      end

      # Truncate the info field at the maximum field length
      res[:info] = res[:info][0, 65535] if res[:info]

      # Truncate the name field at the maximum field length
      res[:name] = res[:name][0, 255] if res[:name]

      res.each do |k, v|
        if host.attribute_names.include?(k.to_s)
          unless host.attribute_locked?(k.to_s)
            host[k] = v.to_s.gsub(/[\x00-\x1f]/n, '')
          end
        else
          dlog("Unknown attribute for Host: #{k}")
        end
      end

      # Set default fields if needed
      host.state       = Msf::HostState::Alive unless host.state
      host.comm        = ''        unless host.comm
      host.workspace   = wspace    unless host.workspace

      host.save! if host.changed?

      host
    end
  end
end
