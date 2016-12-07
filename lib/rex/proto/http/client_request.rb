# frozen_string_literal: true
# -*- coding: binary -*-
require 'uri'
# require 'rex/proto/http'
require 'rex/socket'
require 'rex/text'

require 'pp'

module Rex
  module Proto
    module Http
      class ClientRequest
        DefaultUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        DefaultConfig = {
          #
          # Regular HTTP stuff
          #
          'agent'                  => DefaultUserAgent,
          'cgi'                    => true,
          'cookie'                 => nil,
          'data'                   => '',
          'headers'                => nil,
          'raw_headers'            => '',
          'method'                 => 'GET',
          'path_info'              => '',
          'port'                   => 80,
          'proto'                  => 'HTTP',
          'query'                  => '',
          'ssl'                    => false,
          'uri'                    => '/',
          'vars_get'               => {},
          'vars_post'              => {},
          'version'                => '1.1',
          'vhost'                  => nil,

          #
          # Evasion options
          #
          'encode_params'          => true,
          'encode'                 => false,
          'uri_encode_mode'        => 'hex-normal', # hex-normal, hex-all, hex-noslashes, hex-random, u-normal, u-all, u-noslashes, u-random
          'uri_encode_count'       => 1,       # integer
          'uri_full_url'           => false,   # bool
          'pad_method_uri_count'   => 1,       # integer
          'pad_uri_version_count'  => 1,       # integer
          'pad_method_uri_type'    => 'space', # space, tab, apache
          'pad_uri_version_type'   => 'space', # space, tab, apache
          'method_random_valid'    => false,   # bool
          'method_random_invalid'  => false,   # bool
          'method_random_case'     => false,   # bool
          'version_random_valid'   => false,   # bool
          'version_random_invalid' => false,   # bool
          'uri_dir_self_reference' => false,   # bool
          'uri_dir_fake_relative'  => false,   # bool
          'uri_use_backslashes'    => false,   # bool
          'pad_fake_headers'       => false,   # bool
          'pad_fake_headers_count' => 16,      # integer
          'pad_get_params'         => false,   # bool
          'pad_get_params_count'   => 8,       # integer
          'pad_post_params'        => false,   # bool
          'pad_post_params_count'  => 8,       # integer
          'uri_fake_end'           => false,   # bool
          'uri_fake_params_start'  => false,   # bool
          'header_folding'         => false,   # bool
          'chunked_size'           => 0, # integer

          #
          # NTLM Options
          #
          'usentlm2_session' => true,
          'use_ntlmv2'       => true,
          'send_lm'         => true,
          'send_ntlm'       => true,
          'SendSPN'  => true,
          'UseLMKey' => false,
          'domain' => 'WORKSTATION',
          #
          # Digest Options
          #
          'DigestAuthIIS' => true
        }.freeze

        attr_reader :opts

        def initialize(opts = {})
          @opts = DefaultConfig.merge(opts)
          @opts['headers'] ||= {}
        end

        def to_s
          # Start GET query string
          qstr = opts['query'] ? opts['query'].dup : ""

          # Start POST data string
          pstr = opts['data'] ? opts['data'].dup : ""

          if opts['cgi']
            uri_str = set_uri

            if opts['pad_get_params']
              1.upto(opts['pad_get_params_count'].to_i) do |_i|
                qstr << '&' unless qstr.empty?
                qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32) + 1))
                qstr << '='
                qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32) + 1))
              end
            end
            if opts.key?("vars_get") && opts['vars_get']
              opts['vars_get'].each_pair do |var, val|
                var = var.to_s

                qstr << '&' unless qstr.empty?
                qstr << (opts['encode_params'] ? set_encode_uri(var) : var)
                # support get parameter without value
                # Example: uri?parameter
                next unless val
                val = val.to_s
                qstr << '='
                qstr << (opts['encode_params'] ? set_encode_uri(val) : val)
              end
            end
            if opts['pad_post_params']
              1.upto(opts['pad_post_params_count'].to_i) do |_i|
                rand_var = Rex::Text.rand_text_alphanumeric(rand(32) + 1)
                rand_val = Rex::Text.rand_text_alphanumeric(rand(32) + 1)
                pstr << '&' unless pstr.empty?
                pstr << (opts['encode_params'] ? set_encode_uri(rand_var) : rand_var)
                pstr << '='
                pstr << (opts['encode_params'] ? set_encode_uri(rand_val) : rand_val)
              end
            end

            opts['vars_post'].each_pair do |var, val|
              var = var.to_s
              val = val.to_s

              pstr << '&' unless pstr.empty?
              pstr << (opts['encode_params'] ? set_encode_uri(var) : var)
              pstr << '='
              pstr << (opts['encode_params'] ? set_encode_uri(val) : val)
            end
          else
            qstr = set_encode_uri(qstr) if opts['encode']
            uri_str = set_uri
          end

          req = ''
          req << set_method
          req << set_method_uri_spacer
          req << set_uri_prepend

          req << if opts['encode']
                   set_encode_uri(uri_str)
                 else
                   uri_str
                 end

          unless qstr.empty?
            req << '?'
            req << qstr
          end

          req << set_path_info
          req << set_uri_append
          req << set_uri_version_spacer
          req << set_version
          req << set_host_header

          # If an explicit User-Agent header is set, then use that instead of
          # the default
          unless opts['headers'] && opts['headers'].keys.map(&:downcase).include?('user-agent')
            req << set_agent_header
          end

          # Similar to user-agent, only add an automatic auth header if a
          # manual one hasn't been provided
          unless opts['headers'] && opts['headers'].keys.map(&:downcase).include?('authorization')
            req << set_auth_header
          end

          req << set_cookie_header
          req << set_connection_header
          req << set_extra_headers

          req << set_content_type_header
          req << set_content_len_header(pstr.length)
          req << set_chunked_header
          req << opts['raw_headers']
          req << set_body(pstr)
        end

        protected

        def set_uri
          uri_str = opts['uri'].dup
          uri_str.gsub!('/', '/./') if opts['uri_dir_self_reference']

          if opts['uri_dir_fake_relative']
            buf = ""
            uri_str.split('/', -1).each do |part|
              cnt = rand(8) + 2
              1.upto(cnt) do |_idx|
                buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32) + 1)
              end
              buf << ("/.." * cnt)
              buf << "/" + part
            end
            uri_str = buf
          end

          if opts['uri_full_url']
            url = opts['ssl'] ? "https://" : "http://"
            url << opts['vhost']
            url << (opts['port'] == 80 ? "" : ":#{opts['port']}")
            url << uri_str
            url
          else
            uri_str
          end
        end

        def set_encode_uri(str)
          a = str.to_s.dup
          opts['uri_encode_count'].times do
            a = Rex::Text.uri_encode(a, opts['uri_encode_mode'])
          end
          a
        end

        def set_method
          ret = opts['method'].dup

          ret = ['GET', 'POST', 'HEAD'][rand(3)] if opts['method_random_valid']

          if opts['method_random_invalid']
            ret = Rex::Text.rand_text_alpha(rand(20) + 1)
          end

          ret = Rex::Text.to_rand_case(ret) if opts['method_random_case']

          ret
        end

        def set_method_uri_spacer
          len = opts['pad_method_uri_count'].to_i
          set = " "
          buf = ""

          case opts['pad_method_uri_type']
          when 'tab'
            set = "\t"
          when 'apache'
            set = "\t \x0b\x0c\x0d"
          end

          buf << set[ rand(set.length) ] while buf.length < len

          buf
        end

        #
        # Return the padding to place before the uri
        #
        def set_uri_prepend
          prefix = ""

          prefix << '/%3fa=b/../' if opts['uri_fake_params_start']

          prefix << '/%20HTTP/1.0/../../' if opts['uri_fake_end']

          prefix
        end

        #
        # Return the HTTP path info
        # TODO:
        #  * Encode path information
        def set_path_info
          opts['path_info'] ? opts['path_info'] : ''
        end

        #
        # Return the padding to place before the uri
        #
        def set_uri_append
          # TODO:
          #  * Support different padding types
          ""
        end

        #
        # Return the spacing between the uri and the version
        #
        def set_uri_version_spacer
          len = opts['pad_uri_version_count'].to_i
          set = " "
          buf = ""

          case opts['pad_uri_version_type']
          when 'tab'
            set = "\t"
          when 'apache'
            set = "\t \x0b\x0c\x0d"
          end

          buf << set[ rand(set.length) ] while buf.length < len

          buf
        end

        #
        # Return the HTTP version string
        #
        def set_version
          ret = opts['proto'] + "/" + opts['version']

          if opts['version_random_valid']
            ret = opts['proto'] + "/" + ['1.0', '1.1'][rand(2)]
          end

          if opts['version_random_invalid']
            ret = Rex::Text.rand_text_alphanumeric(rand(20) + 1)
          end

          ret << "\r\n"
        end

        #
        # Return a formatted header string
        #
        def set_formatted_header(var, val)
          if opts['header_folding']
            "#{var}:\r\n\t#{val}\r\n"
          else
            "#{var}: #{val}\r\n"
          end
        end

        #
        # Return the HTTP agent header
        #
        def set_agent_header
          opts['agent'] ? set_formatted_header("User-Agent", opts['agent']) : ""
        end

        def set_auth_header
          opts['authorization'] ? set_formatted_header("Authorization", opts['authorization']) : ""
        end

        #
        # Return the HTTP cookie header
        #
        def set_cookie_header
          opts['cookie'] ? set_formatted_header("Cookie", opts['cookie']) : ""
        end

        #
        # Return the HTTP connection header
        #
        def set_connection_header
          opts['connection'] ? set_formatted_header("Connection", opts['connection']) : ""
        end

        #
        # Return the content type header
        #
        def set_content_type_header
          opts['ctype'] ? set_formatted_header("Content-Type", opts['ctype']) : ""
        end

        #
        # Return the content length header
        #
        def set_content_len_header(clen)
          if opts['method'] == 'GET' && (clen == 0 || opts['chunked_size'] > 0)
            # This condition only applies to GET because of the specs.
            # RFC-7230:
            # A Content-Length header field is normally sent in a POST
            # request even when the value is 0 (indicating an empty payload body)
            return ''
          elsif opts['headers'] && opts['headers']['Content-Length']
            # If the module has a modified content-length header, respect that by
            # not setting another one.
            return ''
          end
          set_formatted_header("Content-Length", clen)
        end

        #
        # Return the HTTP Host header
        #
        def set_host_header
          return "" if opts['uri_full_url']
          host = opts['vhost']

          # IPv6 addresses must be placed in brackets
          host = "[#{host}]" if Rex::Socket.is_ipv6?(host)

          # The port should be appended if non-standard
          host += ":#{opts['port']}" unless [80, 443].include?(opts['port'])

          set_formatted_header("Host", host)
        end

        #
        # Return a string of formatted extra headers
        #
        def set_extra_headers
          buf = ''

          if opts['pad_fake_headers']
            1.upto(opts['pad_fake_headers_count'].to_i) do |_i|
              buf << set_formatted_header(
                Rex::Text.rand_text_alphanumeric(rand(32) + 1),
                Rex::Text.rand_text_alphanumeric(rand(32) + 1)
              )
            end
          end

          opts['headers'].each_pair do |var, val|
            buf << set_formatted_header(var, val)
          end

          buf
        end

        def set_chunked_header
          return "" if opts['chunked_size'] == 0
          set_formatted_header('Transfer-Encoding', 'chunked')
        end

        #
        # Return the HTTP seperator and body string
        #
        def set_body(bdata)
          return "\r\n" + bdata if opts['chunked_size'] == 0
          str = bdata.dup
          chunked = ''
          until str.empty?
            chunk = str.slice!(0, rand(opts['chunked_size']) + 1)
            chunked << sprintf("%x", chunk.size) + "\r\n" + chunk + "\r\n"
          end
          "\r\n" + chunked + "0\r\n\r\n"
        end
        end
      end
  end
end
