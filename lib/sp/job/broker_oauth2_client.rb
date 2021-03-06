#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
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
require 'curb'

module SP
  module Job

    class BrokerOAuth2Client

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
          { :oauth2 => { :error => @code, :error_description => @description } }
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
      # Invalid e-mail or password error.
      #
      class InvalidEmailOrPassword < AccessDenied
        def initialize(a_description="Invalid email or password!")
          super a_description
        end
      end

      #
      # Unauthorized User
      #
      class UnauthorizedUser < Error
        def initialize(a_description)
          super "unauthorized_user", a_description
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

      #
      # Invalid token.
      #
      class InvalidToken < Error
        def initialize(a_description)
          super "invalid_token", a_description
        end
      end

      #
      #
      #
      class CurbConnectionClient

        class Response

          attr_accessor :code
          attr_accessor :body

          @code = nil
          @body = nil

          def initialize(code:, body:)
            @code = code
            @body = body
          end

        end

        def initialize(site_url, connection_options={})
          # set url and connection options
          @site_url = site_url
          @connection_options = connection_options
        end

        def base_url(path)
          @site_url + path
        end

        def send_request(http_method, request_path, options={})

          # options may contain optional arguments like http headers, request parameters etc
          # send http request over the inter-webs

          params          = options[:params] || {}
          headers         = options[:headers]|| {}
          url             = base_url(request_path)
          handle          = Curl::Easy.new(url)
          headers.each do |key, value|
            handle.headers[key] = value
          end

          case http_method
          when :get
            handle.http_get()
            return Response.new(code: handle.response_code.to_s, headers: nil)
          when :post
            args = []
            params.each do |key, value|
              args << Curl::PostField.content(key, value)
            end
            handle.http_post(args)
            return Response.new(code: handle.response_code.to_s, body: handle.body_str)
          when :delete
          when :put
            raise UnhandledHTTPMethodError.new("Unsupported HTTP method, #{http_method}")
          else
            raise UnhandledHTTPMethodError.new("Unsupported HTTP method, #{http_method}")
          end
        end
      end


      private

      @client         = nil
      @redirect_uri   = nil
      @scope          = nil

      public

      #
      # Initializer
      #
      def initialize(protocol:, host:, port:, client_id:, client_secret:, redirect_uri:, scope:, options: {}, endpoints: nil)
        host = "#{protocol}://#{host}"
        if ( 'https' == protocol && 443 != port ) || ( 'http' == protocol && 80 != port )
          host += ":#{port}"
        end
        options.merge!({
          :connection_client => CurbConnectionClient
        })
        @client                = ::OAuth2Client::Client.new(host, client_id, client_secret, options)
        @redirect_uri          = redirect_uri
        @scope                 = scope
        if nil != endpoints
          @client.token_path     = endpoints[:token]         || '/oauth/token'
          @client.authorize_path = endpoints[:authorization] || '/oauth/auth'
        else
          @client.token_path     = '/oauth/token'
          @client.authorize_path = '/oauth/auth'
        end
      end


      #
      # Returns the authorization url, ready to be called.
      #
      def get_authorization_url(a_redirect_uri, a_scope = nil)
        a_scope = @client.normalize_scope(a_scope, ',') if a_scope
        @client.authorization_code.authorization_url({
          redirect_uri: a_redirect_uri,
          scope: a_scope
          })
      end

      #
      # Build and call the authorization url
      #
      # Returns CURL response object.
      #
      def call_authorization_url(a_redirect_uri, a_scope = nil)
        url = get_authorization_url(a_redirect_uri, a_scope)
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
      def get_authorization_code(a_redirect_uri, a_scope = nil)
        url = get_authorization_url(a_redirect_uri || @redirect_uri, a_scope)
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
              if not h[:http][:params][:error]
                raise InternalError.new("Unable to retrieve an authorization code or error!")
              else
                h[:oauth2] = {
                  :error => h[:http][:params][:error]
                }
                if h[:http][:params][:error_description]
                  h[:oauth2][:error_description] = h[:http][:params][:error_description]
                end
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
      # @param a_code
      # @param a_scope
      #
      def exchange_auth_code_for_token(a_code, a_scope = nil)
        unless a_code
          raise InternalError.new("Authorization code expected but was nil!")
        end
        opts = { authenticate: :headers }
        if nil != a_scope
          opts[:params] = { :scope => a_scope }
        end
        response = @client.authorization_code.get_token(a_code, opts)
        h = {
          :http => {
            :status_code => response.code.to_i,
          }
        }
        h[:oauth2] = Hash[ JSON.parse(response.body).to_h.map { |k, v| [k.to_sym, v] }]
        h
      end

      #
      # Refresh an 'access token'.
      #
      # @param a_refresh_token
      # @param a_scope
      #
      def refresh_access_token (a_refresh_token, a_scope = nil)
        unless a_refresh_token
          raise InternalError.new("'refresh token' is expected but is nil!")
        end
        opts = nil != a_scope ? { :params => { :scope => a_scope } } : {}
        response = @client.refresh_token.get_token(a_refresh_token, opts)
        h = {
          :http => {
            :status_code => response.code.to_i,
          }
        }
        h[:oauth2] = Hash[ JSON.parse(response.body).to_h.map { |k, v| [k.to_sym, v] }]
        h
      end

    end # BrokerOAuth2Client

  end # module 'Job'
end # module 'SP'
