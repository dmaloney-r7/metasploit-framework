# frozen_string_literal: true
require 'rex/parser/wapiti_nokogiri'

module Msf::DBManager::Import::Wapiti
  def import_wapiti_xml(args = {}, &block)
    doc = if block
            Rex::Parser::WapitiDocument.new(args, framework.db) { |type, data| yield type, data }
          else
            Rex::Parser::WapitiDocument.new(args, self)
          end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_wapiti_xml_file(args = {})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(data: data))
  end
end
