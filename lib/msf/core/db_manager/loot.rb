# frozen_string_literal: true
module Msf::DBManager::Loot
  #
  # Loot collection
  #
  #
  # This method iterates the loot table calling the supplied block with the
  # instance of each entry.
  #
  def each_loot(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.loots.each do |note|
        yield(note)
      end
    end
  end

  #
  # Find or create a loot matching this type/data
  #
  def find_or_create_loot(opts)
    report_loot(opts)
  end

  #
  # This methods returns a list of all loot in the database
  #
  def loots(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.loots
    end
  end

  def report_loot(opts)
    return unless active
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      path = opts.delete(:path) || (raise "A loot :path is required")

      host = nil
      addr = nil

      # Report the host so it's there for the Proc to use below
      if opts[:host]
        if opts[:host].is_a? ::Mdm::Host
          host = opts[:host]
        else
          host = report_host(workspace: wspace, host: opts[:host])
          addr = normalize_host(opts[:host])
        end
      end

      ret = {}

      ltype  = opts.delete(:type) || opts.delete(:ltype) || (raise "A loot :type or :ltype is required")
      ctype  = opts.delete(:ctype) || opts.delete(:content_type) || 'text/plain'
      name   = opts.delete(:name)
      info   = opts.delete(:info)
      data   = opts[:data]
      loot   = wspace.loots.new

      loot.host_id = host[:id] if host
      if opts[:service] && opts[:service].is_a?(::Mdm::Service)
        loot.service_id = opts[:service][:id]
      end

      loot.path         = path
      loot.ltype        = ltype
      loot.content_type = ctype
      loot.data         = data
      loot.name         = name if name
      loot.info         = info if info
      loot.workspace    = wspace
      msf_import_timestamps(opts, loot)
      loot.save!

      ret[:loot] = loot
    end
  end
end
