# frozen_string_literal: true
# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced features for netware-based
# payloads. NetWare payloads are expected to include this module if
# they want to support these features.
#
###

module Msf::Payload::Netware
  def initialize(info = {})
    ret = super(info)
  end

  #
  # Returns a list of compatible encoders based on architecture
  # fnstenv does not work on NetWare
  #
  def compatible_encoders
    encoders = super()
    encoders2 = []

    encoders.each do |encname, encmod|
      if !encname.include?('fnstenv_mov') && !encname.include?('shikata_ga_nai')
        encoders2 << [ encname, encmod ]
      end
    end

    encoders2
  end
end
