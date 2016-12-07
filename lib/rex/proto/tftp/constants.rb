# frozen_string_literal: true
# -*- coding: binary -*-
require 'rex/proto/tftp'

module Rex
  module Proto
    module TFTP
      OPCODES = %w(Unknown RRQ WRQ DATA ACK ERROR).freeze
      OpRead = 1
      OpWrite = 2
      OpData = 3
      OpAck = 4
      OpError = 5
      OpOptAck = 6

      ERRCODES = [
        "Undefined",
        "File not found",
        "Access violation",
        "Disk full or allocation exceeded",
        "Illegal TFTP operation",
        "Unknown transfer ID",
        "File already exists",
        "No such user",
        "Failed option negotiation"
      ].freeze

      ErrFileNotFound = 1
      ErrAccessViolation = 2
      ErrDiskFull = 3
      ErrIllegalOperation = 4
      ErrUnknownTransferId = 5
      ErrFileExists = 6
      ErrNoSuchUser = 7
      ErrFailedOptNegotiation = 8
      end
  end
end
