# frozen_string_literal: true
module Msf::DBManager::Route
  def report_session_route(session, route)
    return unless active
    s = if session.respond_to? :db_record
          session.db_record
        else
          session
        end
    unless s.respond_to?(:routes)
      raise ArgumentError, "Invalid :session, expected Session object got #{session.class}"
    end

    ::ActiveRecord::Base.connection_pool.with_connection do
      subnet, netmask = route.split("/")
      s.routes.create(subnet: subnet, netmask: netmask)
    end
  end

  def report_session_route_remove(session, route)
    return unless active
    s = if session.respond_to? :db_record
          session.db_record
        else
          session
        end
    unless s.respond_to?(:routes)
      raise ArgumentError, "Invalid :session, expected Session object got #{session.class}"
    end

    ::ActiveRecord::Base.connection_pool.with_connection do
      subnet, netmask = route.split("/")
      r = s.routes.find_by_subnet_and_netmask(subnet, netmask)
      r&.destroy
    end
  end
end
