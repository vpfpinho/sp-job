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

module SP
  module Job

    class BrokerHTTPClient

      ### INNER CLASS(ES) ###

      public

      class Response

        attr_accessor :code
        attr_accessor :headers
        attr_accessor :body

        ### INSTANCE METHOD(S) ###

        def initialize (a_curb_request)
          http_response, *http_headers = a_curb_request.header_str.split(/[\r\n]+/).map(&:strip)
          @code    = a_curb_request.response_code
          @headers = Response.symbolize_keys(Hash[http_headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }])
          @body    = a_curb_request.body
          self
        end

        ### CLASS METHOD(S) ###

        public

        def self.symbolize_keys(a_hash)
          a_hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v.is_a?(Hash) ? symbolize_keys(v) : v }
        end

      end

      class WWWAuthenticateParser
        class SchemeParsingError < StandardError
        end
        class SchemeParser
          def parse(string)
            scheme, attributes_string = split(string)
            raise SchemeParsingError,
                  'No attributes provided' if attributes_string.nil?
            raise SchemeParsingError,
                  %(Unsupported scheme "#{scheme}") unless scheme == 'Bearer'
            parse_attributes(attributes_string)
          end

          def split(string)
            string.split(' ', 2)
          end

          def parse_attributes(string)
            attributes = {}
            string.scan(/(\w+)="([^"]*)"/).each do |group|
              attributes[group[0].to_sym] = group[1]
            end
            attributes
          end
        end
      end

      #
      # Current session data.
      #
      class Session

        attr_accessor :access_token
        attr_accessor :refresh_token
        attr_accessor :scope

        #
        # Initializer
        #
        # @param a_access_token
        # @param a_refresh_token
        # @param a_scope
        #
        def initialize(a_access_token, a_refresh_token, a_scope)
          @access_token  = a_access_token
          @refresh_token = a_refresh_token
          @scope         = a_scope
          self
        end

      end # class Session

      ### METHOD(S) ###

      public

      def session
        # Avoid exposing the original session
        Session.new(
          @session.access_token,
          @session.refresh_token,
          @session.scope
        )
      end

      #
      # Initializer
      #
      # @param a_session
      # @param a_config
      # @param a_options
      #
      def initialize(a_session, a_oauth2_client)
        @session       = a_session
        @oauth2_client = a_oauth2_client
      end

      #
      # Perfom an HTTP GET request and, if required, renew access token.
      #
      # @param a_uri
      # @param a_content_type
      #
      def get(a_uri, a_content_type = 'application/vnd.api+json', a_auto_renew_token = true)
        if true == a_auto_renew_token || nil == @session.access_token
          response = call_and_try_to_recover do
            do_http_get(a_uri, a_content_type)
          end
        else
          do_http_get(a_uri, a_content_type)
        end
      end

      #
      # Perfom an HTTP POST request and, if required, renew access token.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def post(a_uri, a_body, a_content_type = 'application/vnd.api+json', a_auto_renew_token = true)
        if true == a_auto_renew_token || nil == @session.access_token
          response = call_and_try_to_recover do
            do_http_post(a_uri, a_body, a_content_type)
          end
        else
          do_http_post(a_uri, a_body, a_content_type)
        end
      end

      #
      # Perfom a HTTP PATCH request.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def patch(a_uri, a_body, a_content_type = 'application/vnd.api+json')
        if true == a_auto_renew_token || nil == @session.access_token
          response = call_and_try_to_recover do
            do_http_patch(a_uri, a_body, a_content_type)
          end
        else
          do_http_patch(a_uri, a_body, a_content_type)
        end
      end

      #
      # Perfom a HTTP DELETE request.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def delete(a_uri, a_body = nil, a_content_type = 'application/vnd.api+json')
        if true == a_auto_renew_token || nil == @session.access_token
          response = call_and_try_to_recover do
            do_http_delete(a_uri, a_body, a_content_type)
          end
        else
          do_http_delete(a_uri, a_body, a_content_type)
        end
      end

      ### METHOD(S) ###

      private

      #
      # Perfom a HTTP GET request.
      #
      # @param a_uri
      # @param a_content_type
      #
      def do_http_get (a_uri, a_content_type = 'application/vnd.api+json')
        http_request = Curl::Easy.http_get(a_uri) do |curl|
          curl.headers['Content-Type']  = a_content_type;
          curl.headers['Authorization'] = "Bearer #{@session.access_token}"
        end
        Response.new(http_request)
      end

      #
      # Perfom a HTTP POST request.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def do_http_post (a_uri, a_body, a_content_type = 'application/vnd.api+json')
        http_request = Curl::Easy.http_post(a_uri, a_body) do |curl|
          curl.headers['Content-Type']  = a_content_type;
          curl.headers['Authorization'] = "Bearer #{@session.access_token}"
        end
        Response.new(http_request)
      end

      #
      # Perfom a HTTP PATCH request.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def do_http_patch (a_uri, a_body, a_content_type = 'application/vnd.api+json')
        http_request = Curl.http(:PATCH, a_uri, a_body) do |curl|
          curl.headers['Content-Type']  = a_content_type;
          curl.headers['Authorization'] = "Bearer #{@session.access_token}"
        end
        Response.new(http_request)
      end

      #
      # Perfom a HTTP DELETE request.
      #
      # @param a_uri
      # @param a_body
      # @param a_content_type
      #
      def do_http_delete (a_uri, a_body = nil, a_content_type = 'application/vnd.api+json')
        http_request = Curl::Easy.http_delete(a_uri) do |curl|
          curl.headers['Content-Type']   = a_content_type;
          curl.headers['Authorization'] = "Bearer #{@session.access_token}"
        end
        Response.new(http_request)
      end

      #
      # Perform an HTTP request an if 'invalid_token' is returned try to renew
      # access_token and retry request.
      #
      # @param callback
      #
      def call_and_try_to_recover(*callback)
        # pre-request check
        if nil == @session.access_token
          fetch_new_tokens()
        end
        # call http request
        response = yield
        if 401 == response.code && response.headers.has_key?(:'WWW-Authenticate')
          # try to refresh access_token
          tokens_response = @oauth2_client.refresh_access_token(@session.refresh_token, @session.scope)
          if 200 == tokens_response[:http][:status_code] && tokens_response[:oauth2] && ! tokens_response[:oauth2][:error]
            # success: keep track of new data
            @session.access_token  = tokens_response[:oauth2][:access_token]
            @session.refresh_token = tokens_response[:oauth2][:refresh_token]
            @session.scope         = tokens_response[:oauth2][:scope] || @session.scope
            # retry http request
            response = yield
          else
            response = fetch_new_tokens()
          end
        end
        response
      end

      def fetch_new_tokens()
        # failure: request a new 'authorization code'
        auth_code_response = @oauth2_client.get_authorization_code(
          a_redirect_uri = nil,
          a_scope = @session.scope
        )
        # success ?
        if 302 == auth_code_response[:http][:status_code] && auth_code_response[:oauth2] && ! auth_code_response[:oauth2][:error]
          # request new access and refresh tokens
          tokens_response = @oauth2_client.exchange_auth_code_for_token(auth_code_response[:oauth2][:code])
          if 200 == tokens_response[:http][:status_code] && tokens_response[:oauth2] && ! tokens_response[:oauth2][:error]
            # success: keep track of new data
            @session.access_token  = tokens_response[:oauth2][:access_token]
            @session.refresh_token = tokens_response[:oauth2][:refresh_token]
            @session.scope         = tokens_response[:oauth2][:scope] || @session.scope
          end
        end
      end

    end

  end # module Job
end #module SP
