# frozen_string_literal: true
module Msf::DBManager::Ref
  #
  # Find or create a reference matching this name
  #
  def find_or_create_ref(opts)
    ret = {}
    ret[:ref] = get_ref(opts[:name])
    return ret[:ref] if ret[:ref]

    ::ActiveRecord::Base.connection_pool.with_connection do
      ref = ::Mdm::Ref.where(name: opts[:name]).first_or_initialize
      ref.save! if ref && ref.changed?
      ret[:ref] = ref
    end
  end

  def get_ref(name)
    ::ActiveRecord::Base.connection_pool.with_connection do
      ::Mdm::Ref.find_by_name(name)
    end
  end

  #
  # Find a reference matching this name
  #
  def has_ref?(name)
    ::ActiveRecord::Base.connection_pool.with_connection do
      Mdm::Ref.find_by_name(name)
    end
  end
end
