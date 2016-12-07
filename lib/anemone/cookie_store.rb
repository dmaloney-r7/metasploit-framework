# frozen_string_literal: true
require 'delegate'
require 'webrick/cookie'

class WEBrick::Cookie
  def expired?
    !!expires && expires < Time.now
  end
end

module Anemone
  class CookieStore < DelegateClass(Hash)
    def initialize(cookies = nil)
      @cookies = {}
      cookies&.each { |name, value| @cookies[name] = WEBrick::Cookie.new(name, value) }
      super(@cookies)
    end

    def merge!(set_cookie_str)
      cookie_hash = WEBrick::Cookie.parse_set_cookies(set_cookie_str).each_with_object({}) do |cookie, hash|
        hash[cookie.name] = cookie if !!cookie
        hash
      end
      @cookies.merge! cookie_hash
    rescue
    end

    def to_s
      @cookies.values.reject(&:expired?).map { |cookie| "#{cookie.name}=#{cookie.value}" }.join(';')
    end
  end
end
