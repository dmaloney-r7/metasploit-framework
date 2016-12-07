# frozen_string_literal: true
module Msf::Module::ModuleStore
  #
  # Attributes
  #

  #
  # A generic hash used for passing additional information to modules
  #
  attr_accessor :module_store

  #
  # Instance Methods
  #

  #
  # Read a value from the module store
  #
  def [](k)
    module_store[k]
  end

  #
  # Store a value into the module
  #
  def []=(k, v)
    module_store[k] = v
  end
end
