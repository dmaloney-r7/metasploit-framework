# frozen_string_literal: true
module Msf::DBManager::Workspace
  #
  # Creates a new workspace in the database
  #
  def add_workspace(name)
    ::ActiveRecord::Base.connection_pool.with_connection do
      ::Mdm::Workspace.where(name: name).first_or_create
    end
  end

  def default_workspace
    ::ActiveRecord::Base.connection_pool.with_connection do
      ::Mdm::Workspace.default
    end
  end

  def find_workspace(name)
    ::ActiveRecord::Base.connection_pool.with_connection do
      ::Mdm::Workspace.find_by_name(name)
    end
  end

  def workspace
    framework.db.find_workspace(@workspace_name)
  end

  def workspace=(workspace)
    @workspace_name = workspace.name
  end

  def workspaces
    ::ActiveRecord::Base.connection_pool.with_connection do
      ::Mdm::Workspace.order('updated_at asc').load
    end
  end
end
