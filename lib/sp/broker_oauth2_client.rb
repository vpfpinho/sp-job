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

module Sp

	class BrokerOAuth2Client < ::OAuth2Client::Client

		public

		#
		# Configuration
		#
		#	{
		#	 	"protocol": "",
		#	  "host": "",
		#	  "port": 0,
		#	  "endpoints": {
		#	  	"authorization" : "",
		#	  	"token" : ""
		#	  }
		# }
		class Config

			@protocol  = nil
			@host 	   = nil
			@port      = nil
			@endpoints = nil
			@path      = nil
			@base_url  = nil

			attr_accessor :protocol
			attr_accessor :host
			attr_accessor :port
			attr_accessor :endpoints
			attr_accessor :path
			attr_accessor :base_url

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
			end

		end

		private

		#
		#
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
				{ :error => a_code, :error_description => a_description }
			end

	  end

		public

		#
		#
		#
		class AccessDenied < Error

			def initialize(a_description)
				super "access_denied", a_description
			end

		end

		#
		#
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
		def initialize(*args)
			super
			@token_path 	  = '/oauth/token'
			@authorize_path = '/oauth/auth'
		end

		#
		# Returns the authorization url, ready to be called.
		#
		def do_get_authorization_url(opts={})
			opts[:scope] = normalize_scope(opts[:scope], ',') if opts[:scope]
			authorization_code.authorization_url(opts)
		end

		#
		# Build and call the authorization url
		#
		# Returns CURL response object.
		#
		def do_call_authorization_url(opts={})
			url = do_get_authorization_url(opts)
			c = Curl::Easy.http_get(url) do |curl|
				curl.headers['Content-Type'] = "application/json";
			end
			http_response, *http_headers = c.header_str.split(/[\r\n]+/).map(&:strip)
			http_headers = Hash[http_headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }]
			if 302 == c.response_code
				if not http_headers.has_key?('Location')
					raise "Response is missing 'Location' header!"
				end
			end
			Curl::Easy.http_get(http_headers['Location'])
		end

		#
		# Build and call the authorization url.
		#
		# Returns an hash with http data and oauth2 authorization code.
		#
		def do_get_authorization_code(opts={})
			url = do_get_authorization_url(opts)
			c = Curl::Easy.http_get(url) do |curl|
				curl.headers['Content-Type'] = "application/json";
			end
			http_response, *http_headers = c.header_str.split(/[\r\n]+/).map(&:strip)
			http_headers = Hash[http_headers.flat_map{ |s| s.scan(/^(\S+): (.+)/) }]
			if 302 == c.response_code
				if not http_headers.has_key?('Location')
					raise "Response is missing 'Location' header!"
				end
				if false == http_headers['Location'].start_with?("#{opts[:redirect_uri]}")
					raise "Unable to parse 'Location'"
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
							raise AccessDenied, h[:http][:params][:error], h[:http][:params][:error_description]
						else
							raise InternalError, "Unable to retrieve an authorization code!"
						end
					else
						h[:oauth2] = {
							:code => h[:http][:params][:code]
						}
					end
					h
				else
					raise "Unexpected HTTP status code #{c.response_code}!"
				end
			end

			#
			# Exchange an 'authorization code' for access ( and refresh ) token(s).
			#
			def do_exchange_auth_code_for_token(opts={})
				unless (opts[:params] && opts[:params][:code])
					raise "Authorization code expected but was nil"
				end
				opts[:authenticate] = :headers
				code = opts[:params].delete(:code)
				response = authorization_code.get_token(code, opts)
				if 200 == response.code.to_i
					Hash[ JSON.parse(response.body).to_h.map { |k, v| [k.to_sym, v] }]
				else
					# TODO
					nil
				end
			end

		end

end # module 'Sp'
