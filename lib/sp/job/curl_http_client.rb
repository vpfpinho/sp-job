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

#
# A helper class to do HTTP request without session management.
#

require 'curb'
require_relative 'easy_http_client'
require_relative 'jsonapi_error'

module Curl
  class Easy
    class << self
      def http_patch(*args)
        url = args.shift
        c = Curl::Easy.new url
        yield c if block_given?
        body = args.shift
        if nil != body
          c.headers["Content-Length"] = body.bytesize
          c.put_data = body
        end
        c.http(:PATCH)
        c
      end
    end
  end
end

module SP
  module Job

    class CurlHTTPClient < EasyHttpClient

       ### INSTANCE METHODS ###

      def head(url:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.head(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def get(url:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.get(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.post(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.put(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.patch(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def delete(url:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.delete(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def upload(origin:, url:, headers: nil, body:, expect: nil, conn_options: nil)
        CurlHTTPClient.upload(origin: origin, url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def get_to_file(url:, headers: nil, to:, expect: nil, conn_options: nil)
        CurlHTTPClient.get_to_file(url: url, headers: headers, to: to, expect: expect, conn_options: conn_options)
      end

      def post_to_file(url:, headers: nil, body:, to:, expect: nil, conn_options: nil)
        CurlHTTPClient.post_to_file(url: url, headers: headers, body: body, to: to, expect: expect, conn_options: conn_options)
      end

      def post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.post_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.put_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        CurlHTTPClient.patch_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      ### STATIC METHODS ###
          
      #
      # Perform an HTTP HEAD request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.head(url:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'HEAD', url: url) do
          r = Curl::Easy.http_head(url) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'HEAD', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'get'

      #
      # Perform an HTTP GET request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.get(url:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'GET', url: url) do
          r = Curl::Easy.http_get(url) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'GET', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'get'

      #
      # Perform an HTTP POST request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [OPTIONAL] Data to send.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        response = call(method: 'POST', url: url) do
          r = Curl::Easy.http_post(url, body) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'POST', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'post'

      #
      # Perform an HTTP PUT request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [OPTIONAL] Data to send.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        response = call(method: 'PUT', url: url) do
          r = Curl::Easy.http_put(url, body) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'PUT', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'put'

      #
      # Perform an HTTP PATCH request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [OPTIONAL] Data to send.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        response = call(method: 'PATCH', url: url) do
          r = Curl::Easy.http_patch(url, body) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'PATCH', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'patch'

      #
      # Perform an HTTP DELETE request
      #
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'DELETE', url: url) do
          r = nil
          begin
            r = Curl::Easy.http_delete(url) do | h |
              set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
            end
            response = normalize_response(curb_r: r)
          rescue Curl::Err::GotNothingError
            response = {:code => 204}
          end
          raise_if_not_expected(method: 'DELETE', url: url, response: response, expect: expect)
        end
      end # method 'delete'

      #
      # Perform an HTTP POST request to upload some data.
      #
      # [ WARNING - USAGE INTENDED ONLY FOR DEBUG / TESTING PROPOSES - WORKS ONLY WITH CURB ]
      #
      # @oaram origin       [REQUIRED] HTTP Origin header value.
      # @param url          [REQUIRED] Request URL.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [REQUIRED] Data to send.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.upload(origin:, url:, headers: nil, body:, expect: nil, conn_options: nil)
        if ( nil == headers )
          headers = {}        
        end
        headers.merge!({ 
            'Content-Type' => 'application/octet-stream', 
            'Origin' => origin,
            'Content-Disposition' => 'attachment'
            }
        )
        response = call(method: 'POST', url: url) do
          r = Curl::Easy.http_post(url, body) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'POST', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end # method 'upload'

      #
      # Perform an HTTP GET and write contents to a file
      #
      # @param url          [REQUIRED] URL
      # @param headers      [OPTIONAL] Request specific headers.
      # @param to           [REQUIRED] Local file URI.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.get_to_file(url:, headers: nil, to:, expect: nil, conn_options: nil)
        response = call(method: 'GET', url: url, local_file_uri: url) do
          r = Curl::Easy.new
          r.url = url
          set_handle_properties(handle: r, headers: headers, conn_options: conn_options)
          File.open(to, 'wb') do | f |
            r.on_body { | data | f << data; data.size }
            r.perform
          end
          raise_if_not_expected(method: 'GET', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end

      #
      # Perform an HTTP GET and write response contents to a file
      #
      # @param url          [REQUIRED] URL
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [OPTIONAL] Data to send.
      # @param to           [REQUIRED] Local file URI.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.post_to_file(url:, headers: nil, body:, to:, expect: nil, conn_options: nil)
        response = call(method: 'POST', url: url, local_file_uri: url) do
          r = Curl::Easy.new
          r.url = url
          if nil != body
            r.headers["Content-Length"] = body.bytesize
            r.put_data = body
          end
          set_handle_properties(handle: r, headers: headers, conn_options: conn_options)
          File.open(to, 'wb') do | f |
            r.on_body { | data | f << data; data.size }
            r.http(:POST)
          end
          raise_if_not_expected(method: 'POST', url: url, response: normalize_response(curb_r: r), expect: expect)
        end
      end

      #
      # Perform an HTTP POST request to send a file
      #
      # @param uri          [REQUIRED] Local file URI.
      # @param to           [REQUIRED] URI.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param body         [OPTIONAL] Data to send.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'POST', url: to, local_file_uri: uri) do
          r = nil
          File.open(uri, 'rb') do | f |
            r = Curl::Easy.http_post(to, f.read) do | h |
              set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
            end
          end
          raise_if_not_expected(method: 'POST', url: to, response: normalize_response(curb_r: r), expect: expect)
        end
      end
      
      #
      # Perform an HTTP POST request to send a file
      #
      # @param uri          [REQUIRED] Local file URI.
      # @param to           [REQUIRED] URI.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'PUT', url: to, local_file_uri: uri) do
          r = nil
          File.open(uri, 'rb') do | f |
            r = Curl::Easy.http_put(to, f.read) do | h |
              set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
            end
          end
          raise_if_not_expected(method: 'PUT', url: to, response: normalize_response(curb_r: r), expect: expect)
        end
      end

      #
      # Perform an HTTP PATCH request to send a file
      #
      # @param uri          [REQUIRED] Local file URI.
      # @param to           [REQUIRED] URI.
      # @param headers      [OPTIONAL] Request specific headers.
      # @param expect       [OPTIONAL] { code: <numeric>, content: { type: <string>} }
      # @param conn_options [OPTIONAL] TODO
      #
      def self.patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        response = call(method: 'PATCH', url: to, local_file_uri: uri) do
          r = nil
          File.open(uri, 'rb') do | f |
            r = Curl::Easy.http_patch(to, f.read) do | h |
              set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
            end
          end
          raise_if_not_expected(method: 'PATCH', url: to, response: normalize_response(curb_r: r), expect: expect)
        end
      end

      private

      #
      # Set a CURL handle properties
      #
      # @param handle
      # @param headers
      # @param conn_options
      #
      def self.set_handle_properties(handle:, headers:, conn_options:)
        # connection timeout
        conn_options = conn_options || {}
        if conn_options[:connection_timeout]
          handle.connect_timeout = conn_options[:connection_timeout]
        end
        # request timeout
        if conn_options[:request_timeout]
          handle.timeout = conn_options[:request_timeout]
        end
        # set other headers
        { 'User-Agent' => 'SP-JOB/CurlHTTPClient' }.merge(headers || {}).each do |k,v|
          handle.headers[k] = v
        end
      end

      #
      # Normalize CURL response
      #
      # @param curb_r
      #
      def self.normalize_response(curb_r:)
        http_response, *http_headers = curb_r.header_str.split(/[\r\n]+/).map(&:strip)
        o = {
          code: curb_r.response_code,
          body: curb_r.body,
          description: http_reason(code: curb_r.response_code),
          content: {
            type: nil,
            length: 0
          }
         }
        http_headers.each do |header|
          m = header.match("(^Content-Type){1}:\s(.*){1}")
          if nil != m && 3 == m.length
            o[:content][:type] = m[2]
          end
          m = header.match("(^Content-Length){1}:\s\([0-9]+){1}")
          if nil != m && 3 == m.length
            o[:content][:length] = m[2].to_i
          end
        end
        o
      end

      #
      # Call a method and catch / translate error(s)
      #
      # @param method
      # @param url
      # @param localfile_uri
      # @param block
      #
      def self.call(method:, url:, local_file_uri: nil, &block)
        begin
          response = yield
        rescue Curl::Err::ConnectionFailedError => connection_error
          raise ::SP::Job::EasyHttpClient::CouldNotNonnect.new(method: method, url: url)
        rescue Curl::Easy::Error => curl_error
          raise ::SP::Job::EasyHttpClient::InternalError.new(method: method, url: url, object: curl_error, response: response)
        rescue Errno::ENOENT => not_found
          raise ::SP::Job::EasyHttpClient::SourceFileNotFound.new(method: method, url: url, local_file_uri: local_file_uri)
        end
        response
      end

    end # class 'CurlHTTPClient'

  end # module 'Job'
end # module 'SP'
