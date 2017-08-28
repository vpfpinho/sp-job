#
# Copyright (c) 2011-2016 Servicepartner LDA. All rights reserved.
#
# This file is part of sp-job.
#
# sp-job is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sp-job is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with sp-job.  If not, see <http://www.gnu.org/licenses/>.
#
# encoding: utf-8
#

# https://github.com/tiabas/oauth2-client

require 'oauth2'
require 'oauth2-client'

module SP
  module Job

    class BrokerOAuth2Client < ::OAuth2Client::Client

      public

      #
      # Configuration
      #
      # {
      #   "protocol": "",
      #   "host": "",
      #   "port": 0,
      #   "endpoints": {
      #     "authorization" : "",
      #     "token" : ""
      #   }
      # }
      class Config

        @protocol      = nil
        @host          = nil
        @port          = nil
        @endpoints     = nil
        @path          = nil
        @base_url      = nil
        @client_id     = nil
        @client_secret = nil
        @redirect_uri  = nil
        @scope         = nil

        attr_accessor :protocol
        attr_accessor :host
        attr_accessor :port
        attr_accessor :endpoints
        attr_accessor :path
        attr_accessor :base_url

        attr_accessor :client_id
        attr_accessor :client_secret
        attr_accessor :redirect_uri
        attr_accessor :scope

        def initialize(a_hash)
          @protocol  = a_hash[:protocol]
          @host      = a_hash[:host]
          @port      = a_hash[:port]
          @path      = a_hash[:path]
          @endpoints = {
            :authorization => a_hash[:endpoints][:authorization],
            :token => a_hash[:endpoints][:token]
          }
          @path     = nil
          @base_url = "#{@protocol}://#{@host}"
          if @port && 80 != @port
            @base_url += ":#{@port}"
          end
          if @path
            @base_url += "#{@path}"
          end
          @client_id     = a_hash[:client_id]
          @client_secret = a_hash[:client_secret]
          @redirect_uri  = a_hash[:redirect_uri]
          @scope         = a_hash[:scope]
        end

      end

      private

      #
      # Generic error.
      #
      class Error < StandardError

        @code        = nil
        @description = nil

        attr_accessor :code
        attr_accessor :description

        def initialize(a_code, a_description)
          @code        = a_code
          @description = a_description
        end

        def as_hash
          { :error => @code, :error_description => @description }
        end

      end

      public

      #
      # Access denied error.
      #
      class AccessDenied < Error

        def initialize(a_description)
          super "access_denied", a_description
        end

      end

      #
      # Internal error.
      #
      class InternalError < Error

        def initialize(a_description)
          super "internal_error", a_description
        end

      end

      public

      #
      # Initializer
      #
      def initialize(a_host, a_client_id, a_client_secret, a_options = {})
        super(a_host, a_client_id, a_client_secret, a_options)
        @token_path     = '/oauth/token'
        @authorize_path = '/oauth/auth'
      end

      #
      # Returns the authorization url, ready to be called.
      #
      def do_get_authorization_url(a_redirect_uri, a_scope = nil)
        a_scope = normalize_scope(a_scope, ',') if a_scope
        authorization_code.authorization_url({
          redirect_uri: a_redirect_uri,
          scope: a_scope
        })
      end

      #
      # Build and call the authorization url
      #
      # Returns CURL response object.
      #
      def do_call_authorization_url(a_redirect_uri, a_scope = nil)
        url = do_get_authorization_url(a_redirect_uri, a_scope)
        c = Curl::Easy.http_get(url) do |curl|
          curl.headers['Content-Type'] = "application/json";
        end
        http_response, *http_headers = c.header_str.split(/[\r\n]+/).map(&:strip)
        http_headers = Hash[http_headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }]
        if 302 == c.response_code
          if not http_headers.has_key?('Location')
            raise InternalError.new("Response is missing 'Location' header!")
          end
        end
        Curl::Easy.http_get(http_headers['Location'])
      end

      #
      # Build and call the authorization url.
      #
      # Returns an hash with http data and oauth2 authorization code.
      #
      def do_get_authorization_code(a_redirect_uri, a_scope = nil)
        url = do_get_authorization_url(a_redirect_uri, a_scope)
        c = Curl::Easy.http_get(url) do |curl|
          curl.headers['Content-Type'] = "application/json";
        end
        http_response, *http_headers = c.header_str.split(/[\r\n]+/).map(&:strip)
        http_headers = Hash[http_headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }]
        if 302 == c.response_code
          if not http_headers.has_key?('Location')
            raise InternalError.new("Response is missing 'Location' header!")
          end
          if false == http_headers['Location'].start_with?("#{a_redirect_uri}")
            raise InternalError.new("Unable to parse 'Location'")
          end
          h = {
            :http => {
              :status_code => c.response_code,
              :location    => http_headers['Location'],
              :params      => Hash[ URI::decode_www_form(URI(http_headers['Location']).query).to_h.map { |k, v| [k.to_sym, v] }]
              },
            }
          if not h[:http][:params][:code]
            if h[:http][:params][:error]
              raise Error.new(h[:http][:params][:error], h[:http][:params][:error_description])
            else
              raise InternalError.new("Unable to retrieve an authorization code!")
            end
          else
            h[:oauth2] = {
              :code => h[:http][:params][:code]
            }
          end
          h
        else
          raise InternalError.new("Unable to retrieve an authorization code - unexpected HTTP status code #{c.response_code}!")
        end
      end

      #
      # Exchange an 'authorization code' for access ( and refresh ) token(s).
      #
      def do_exchange_auth_code_for_token(a_code)
        unless a_code
          raise InternalError.new("Authorization code expected but was nil!")
        end
        response = authorization_code.get_token(a_code, {
          authenticate: :headers
        })
        h = {
          :http => {
            :status_code => response.code.to_i,
          }
        }
        # if 200 == response.code.to_i
        # end
        h[:oauth2] = Hash[ JSON.parse(response.body).to_h.map { |k, v| [k.to_sym, v] }]
        h
      end

    end

  end # module 'Job'
end # module 'SP'
