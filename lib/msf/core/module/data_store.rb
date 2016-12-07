# frozen_string_literal: true
module Msf::Module::DataStore
  #
  # Attributes
  #

  # @attribute [r] datastore
  #   The module-specific datastore instance.
  #
  #   @return [Hash{String => String}]
  attr_reader :datastore

  #
  # Imports default options into the module's datastore, optionally clearing
  # all of the values currently set in the datastore.
  #
  def import_defaults(clear_datastore = true)
    # Clear the datastore if the caller asked us to
    datastore.clear if clear_datastore

    datastore.import_options(options, 'self', true)

    # If there are default options, import their values into the datastore
    if module_info['DefaultOptions']
      datastore.import_options_from_hash(module_info['DefaultOptions'], true, 'self')
    end
  end

  #
  # Overrides the class' own datastore with the one supplied.  This is used
  # to allow modules to share datastores, such as a payload sharing an
  # exploit module's datastore.
  #
  def share_datastore(ds)
    self.datastore = ds
    datastore.import_options(options)
  end

  protected

  attr_writer :datastore
end
