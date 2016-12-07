# frozen_string_literal: true
require 'rex/parser/acunetix_nokogiri'

module Msf::DBManager::Import::Acunetix
  def import_acunetix_noko_stream(args = {}, &block)
    doc = if block
            Rex::Parser::AcunetixDocument.new(args, framework.db) { |type, data| yield type, data }
          else
            Rex::Parser::AcunetixFoundstoneDocument.new(args, self)
          end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_acunetix_xml(args = {}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_acunetix_noko_stream(noko_args) { |type, data| yield type, data }
      else
        import_acunetix_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise Msf::DBImportError, "Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'."
    end
  end
end
