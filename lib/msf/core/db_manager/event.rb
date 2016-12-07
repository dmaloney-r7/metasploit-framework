# frozen_string_literal: true
module Msf::DBManager::Event
  def events(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.events.find :all, order: 'created_at ASC'
    end
  end

  def report_event(opts = {})
    return unless active
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      return unless wspace # Temp fix?
      uname = opts.delete(:username)

      if !opts[:host].is_a?(::Mdm::Host) && opts[:host]
        opts[:host] = report_host(workspace: wspace, host: opts[:host])
      end

      ::Mdm::Event.create(opts.merge(workspace_id: wspace[:id], username: uname))
    end
  end
end
