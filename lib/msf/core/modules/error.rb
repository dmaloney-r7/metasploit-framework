# frozen_string_literal: true
# -*- coding: binary -*-
# Base error class for all error under {Msf::Modules}
class Msf::Modules::Error < StandardError
  def initialize(attributes = {})
    @module_path = attributes[:module_path]
    @module_reference_name = attributes[:module_reference_name]

    message_parts = []
    message_parts << "Failed to load module"

    if module_reference_name || module_path
      clause_parts = []

      clause_parts << module_reference_name if module_reference_name

      clause_parts << "from #{module_path}" if module_path

      clause = clause_parts.join(' ')
      message_parts << "(#{clause})"
    end

    causal_message = attributes[:causal_message]

    message_parts << "due to #{causal_message}" if causal_message

    message = message_parts.join(' ')

    super(message)
  end

  attr_reader :module_reference_name
  attr_reader :module_path
end
