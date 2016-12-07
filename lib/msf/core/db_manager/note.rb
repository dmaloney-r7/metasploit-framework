# frozen_string_literal: true
module Msf::DBManager::Note
  #
  # This method iterates the notes table calling the supplied block with the
  # note instance of each entry.
  #
  def each_note(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.notes.each do |note|
        yield(note)
      end
    end
  end

  #
  # Find or create a note matching this type/data
  #
  def find_or_create_note(opts)
    report_note(opts)
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.notes
    end
  end

  #
  # Report a Note to the database.  Notes can be tied to a ::Mdm::Workspace, Host, or Service.
  #
  # opts MUST contain
  # +:type+::  The type of note, e.g. smb_peer_os
  #
  # opts can contain
  # +:workspace+::  the workspace to associate with this Note
  # +:host+::       an IP address or a Host object to associate with this Note
  # +:service+::    a Service object to associate with this Note
  # +:data+::       whatever it is you're making a note of
  # +:port+::       along with +:host+ and +:proto+, a service to associate with this Note
  # +:proto+::      along with +:host+ and +:port+, a service to associate with this Note
  # +:update+::     what to do in case a similar Note exists, see below
  #
  # The +:update+ option can have the following values:
  # +:unique+::       allow only a single Note per +:host+/+:type+ pair
  # +:unique_data+::  like +:uniqe+, but also compare +:data+
  # +:insert+::       always insert a new Note even if one with identical values exists
  #
  # If the provided +:host+ is an IP address and does not exist in the
  # database, it will be created.  If +:workspace+, +:host+ and +:service+
  # are all omitted, the new Note will be associated with the current
  # workspace.
  #
  def report_note(opts)
    return unless active
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      wspace = find_workspace(wspace) if wspace.is_a? String
      seen = opts.delete(:seen) || false
      crit = opts.delete(:critical) || false
      host = nil
      addr = nil
      # Report the host so it's there for the Proc to use below
      if opts[:host]
        if opts[:host].is_a? ::Mdm::Host
          host = opts[:host]
        else
          addr = normalize_host(opts[:host])
          host = report_host(workspace: wspace, host: addr)
        end
        # Do the same for a service if that's also included.
        if opts[:port]
          proto = nil
          sname = nil
          proto_lower = opts[:proto].to_s.downcase # Catch incorrect usages
          case proto_lower
          when 'tcp', 'udp'
            proto = proto_lower
            sname = opts[:sname] if opts[:sname]
          when 'dns', 'snmp', 'dhcp'
            proto = 'udp'
            sname = opts[:proto]
          else
            proto = 'tcp'
            sname = opts[:proto]
          end
          sopts = {
            workspace: wspace,
            host: host,
            port: opts[:port],
            proto: proto
          }
          sopts[:name] = sname if sname
          report_service(sopts)
        end
      end
      # Update Modes can be :unique, :unique_data, :insert
      mode = opts[:update] || :unique

      ret = {}

      host = get_host(workspace: wspace, host: addr) if addr && !host
      if host && (opts[:port] && opts[:proto])
        service = get_service(wspace, host, opts[:proto], opts[:port])
      elsif opts[:service] && opts[:service].is_a?(::Mdm::Service)
        service = opts[:service]
      end
      #     if host
      #       host.updated_at = host.created_at
      #       host.state      = HostState::Alive
      #       host.save!
      #     end
      ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise "A note :type or :ntype is required")
      data   = opts[:data]
      note   = nil

      conditions = { ntype: ntype }
      conditions[:host_id] = host[:id] if host
      conditions[:service_id] = service[:id] if service
      conditions[:vuln_id] = opts[:vuln_id]

      case mode
      when :unique
        note      = wspace.notes.where(conditions).first_or_initialize
        note.data = data
      when :unique_data
        notes = wspace.notes.where(conditions)

        # Don't make a new Note with the same data as one that already
        # exists for the given: type and (host or service)
        notes.each do |n|
          # Compare the deserialized data from the table to the raw
          # data we're looking for.  Because of the serialization we
          # can't do this easily or reliably in SQL.
          if n.data == data
            note = n
            break
          end
        end
        unless note
          # We didn't find one with the data we're looking for, make
          # a new one.
          note = wspace.notes.new(conditions.merge(data: data))
        end
      else
        # Otherwise, assume :insert, which means always make a new one
        note = wspace.notes.new
        note.host_id = host[:id] if host
        if opts[:service] && opts[:service].is_a?(::Mdm::Service)
          note.service_id = opts[:service][:id]
        end
        note.seen     = seen
        note.critical = crit
        note.ntype    = ntype
        note.data     = data
      end
      note.vuln_id = opts[:vuln_id] if opts[:vuln_id]
      msf_import_timestamps(opts, note)
      note.save!
      ret[:note] = note
    end
  end
end
