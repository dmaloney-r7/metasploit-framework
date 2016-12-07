# frozen_string_literal: true
module Msf::DBManager::Service
  # Deletes a port and associated vulns matching this port
  def del_service(wspace, address, proto, port, _comm = '')
    host = get_host(workspace: wspace, address: address)
    return unless host

    ::ActiveRecord::Base.connection_pool.with_connection do
      host.services.where(proto: proto, port: port).each(&:destroy)
    end
  end

  # Iterates over the services table calling the supplied block with the
  # service instance of each entry.
  def each_service(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      services(wspace).each do |service|
        yield(service)
      end
    end
  end

  def find_or_create_service(opts)
    report_service(opts)
  end

  def get_service(wspace, host, proto, port)
    ::ActiveRecord::Base.connection_pool.with_connection do
      host = get_host(workspace: wspace, address: host)
      return unless host
      return host.services.find_by_proto_and_port(proto, port)
    end
  end

  #
  # Record a service in the database.
  #
  # opts MUST contain
  # +:host+::  the host where this service is running
  # +:port+::  the port where this service listens
  # +:proto+:: the transport layer protocol (e.g. tcp, udp)
  #
  # opts may contain
  # +:name+::  the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+:: an alias for the above
  # +:workspace+:: the workspace for the service
  #
  def report_service(opts)
    return unless active
    ::ActiveRecord::Base.connection_pool.with_connection do |_conn|
      addr  = opts.delete(:host) || return
      hname = opts.delete(:host_name)
      hmac  = opts.delete(:mac)
      host  = nil
      wspace = opts.delete(:workspace) || workspace
      hopts = { workspace: wspace, host: addr }
      hopts[:name] = hname if hname
      hopts[:mac]  = hmac  if hmac

      # Other report_* methods take :sname to mean the service name, so we
      # map it here to ensure it ends up in the right place despite not being
      # a real column.
      opts[:name] = opts.delete(:sname) if opts[:sname]

      if addr.is_a? ::Mdm::Host
        host = addr
        addr = host.address
      else
        host = report_host(hopts)
      end

      if opts[:port].to_i.zero?
        dlog("Skipping port zero for service '%s' on host '%s'" % [opts[:name], host.address])
        return nil
      end

      ret = {}
      #     host = get_host(:workspace => wspace, :address => addr)
      #     if host
      #       host.updated_at = host.created_at
      #       host.state      = HostState::Alive
      #       host.save!
      #     end

      proto = opts[:proto] || Msf::DBManager::DEFAULT_SERVICE_PROTO

      service = host.services.where(port: opts[:port].to_i, proto: proto).first_or_initialize
      opts.each do |k, v|
        if service.attribute_names.include?(k.to_s)
          service[k] = (v && (k == :name) ? v.to_s.downcase : v)
        else
          dlog("Unknown attribute for Service: #{k}")
        end
      end
      service.state ||= Msf::ServiceState::Open
      service.info  ||= ""

      if service && service.changed?
        msf_import_timestamps(opts, service)
        service.save!
      end

      if opts[:task]
        Mdm::TaskService.create(
          task: opts[:task],
          service: service
        )
      end

      ret[:service] = service
    end
  end

  # Returns a list of all services in the database
  def services(wspace = workspace, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
    ::ActiveRecord::Base.connection_pool.with_connection do
      conditions = {}
      conditions[:state] = [Msf::ServiceState::Open] if only_up
      conditions[:proto] = proto if proto
      conditions["hosts.address"] = addresses if addresses
      conditions[:port] = ports if ports
      conditions[:name] = names if names
      wspace.services.includes(:host).where(conditions).order("hosts.address, port")
    end
  end
end
