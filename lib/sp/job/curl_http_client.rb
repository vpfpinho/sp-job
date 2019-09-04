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
          c.headers["Content-Length"] = body.length
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
          r = Curl::Easy.http_delete(url) do | h |
            set_handle_properties(handle: h, headers: headers, conn_options: conn_options)
          end
          raise_if_not_expected(method: 'DELETE', url: url, response: normalize_response(curb_r: r), expect: expect)
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
            o[:content][:length] = m[2]
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
        rescue Errno::ENOENT => not_found
          raise ::SP::Job::EasyHttpClient::SourceFileNotFound.new(method: method, url: url, local_file_uri: local_file_uri)
        rescue Curl::Easy::Error => curl_error
          raise ::SP::Job::EasyHttpClient::InternalError.new(method: method, url: url, object: curl_error, response: response)
        rescue ::SP::Job::EasyHttpClient::Error => ece
          raise ece
        rescue StandardError => se
          raise ::SP::Job::EasyHttpClient::InternalError.new(method: method, url: url, object: se, response: response)
        rescue RuntimeError => rte
          raise ::SP::Job::EasyHttpClient::InternalError.new(method: method, url: url, object: rte, response: response)
        rescue Exception => e
          raise ::SP::Job::EasyHttpClient::InternalError.new(method: method, url: url, object: e, response: response)
        end
        response
      end

    end # class 'CurlHTTPClient'

  end # module 'Job'
end # module 'SP'
