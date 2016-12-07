# frozen_string_literal: true
module Msf::DBManager::Import::Qualys
  autoload :Asset, 'msf/core/db_manager/import/qualys/asset'
  autoload :Scan, 'msf/core/db_manager/import/qualys/scan'

  include Msf::DBManager::Import::Qualys::Asset
  include Msf::DBManager::Import::Qualys::Scan

  #
  # Qualys report parsing/handling
  #
  def handle_qualys(wspace, hobj, port, protocol, qid, _severity, refs, name = nil, title = nil, task = nil)
    addr = hobj.address
    port = port.to_i if port

    info = { workspace: wspace, host: hobj, port: port, proto: protocol, task: task }
    if name && (name != 'unknown') && (name != 'No registered hostname')
      info[:name] = name
    end

    report_service(info) if info[:host] && info[:port] && info[:proto]

    fixed_refs = []
    refs&.each do |ref|
      fixed_refs << case ref
                    when /^MS[0-9]{2}-[0-9]{3}/
                      "MSB-#{ref}"
                    else
                      ref
                    end
    end

    return if qid == 0
    title = 'QUALYS-' + qid if title.nil? || title.empty?
    if addr
      report_vuln(
        workspace: wspace,
        task: task,
        host: hobj,
        port: port,
        proto: protocol,
        name: title,
        refs: fixed_refs
      )
    end
  end
end
