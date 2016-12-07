# frozen_string_literal: true
class Anemone::Extractors::Frames < Anemone::Extractors::Base
  def run
    doc.css('frame', 'iframe').map do |a|
      begin
                                             a.attributes['src'].content
                                           rescue
                                             next
                                           end
    end
  end
end
