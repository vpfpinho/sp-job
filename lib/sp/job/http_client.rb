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

require_relative 'curl_http_client' unless 'jruby' == RUBY_ENGINE
require_relative 'java_http_client' if     'jruby' == RUBY_ENGINE

require 'awesome_print'

module SP
  module Job
    class HttpClient < EasyHttpClient

      attr_accessor :user_agent, :mandatory_headers

      private

        @headers = nil

      public

      def initialize(owner:, headers:, mandatory_headers: nil)
        @headers = {
          'User-Agent' => "#{HttpClient.get_klass.name()}/#{owner || 'unknown'}"
        }.merge(headers)

        @mandatory_headers = mandatory_headers
      end

      def head(url:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.head(url: url, headers: ensure_headers(headers: headers), expect: expect, conn_options: conn_options)
      end

      def get(url:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.get(url: url, headers: ensure_headers(headers: headers), expect: expect, conn_options: conn_options)
      end

      def post(url:, headers: nil, body:, expect: nil, conn_options: nil)
        HttpClient.post(url: url, headers: ensure_headers(headers: headers), body: body, expect: expect, conn_options: conn_options)
      end

      def put(url:, headers: nil, body:, expect: nil, conn_options: nil)
        HttpClient.put(url: url, headers: ensure_headers(headers: headers), body: body, expect: expect, conn_options: conn_options)
      end

      def patch(url:, headers: nil, body:, expect: nil, conn_options: nil)
        HttpClient.patch(url: url, headers: ensure_headers(headers: headers), body: body, expect: expect, conn_options: conn_options)
      end

      def delete(url:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.delete(url: url, headers: ensure_headers(headers: headers), expect: expect, conn_options: conn_options)
      end

      def upload(origin:, url:, headers: nil, body:, expect: nil, conn_options: nil)
        HttpClient.upload(origin: origin, url: url, headers: ensure_headers(headers: headers), body: body, expect: expect, conn_options: conn_options)
      end

      def post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.post_file(uri: uri, to: to, headers: ensure_headers(headers: headers), expect: expect, conn_options: conn_options)
      end

      def put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.put_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        HttpClient.patch_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end
    
      private

      def ensure_headers(headers:)
        merged_headers = @headers.merge( headers || {} )
        missing_headers = @mandatory_headers.map { |header| merged_headers.keys.include?(header) ? nil : header }.compact

        if !missing_headers.empty?
          raise MissingRequiredHeadersError.new("The following headers are mandatory #{missing_headers.join(', ')}")
        end

        return merged_headers
      end

      def self.get_klass
        'jruby' == RUBY_ENGINE ? JavaHTTPClient : CurlHTTPClient
      end

      def self.head(url:, headers: nil, expect: nil, conn_options: nil)
        get_klass.head(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.get(url:, headers: nil, expect: nil, conn_options: nil)
        get_klass.get(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.post(url:, headers: nil, body:, expect:, conn_options: nil)
        get_klass.post(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def self.put(url:, headers: nil, body:, expect:, conn_options: nil)
        get_klass.put(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def self.patch(url:, headers: nil, body:, expect:, conn_options: nil)
        get_klass.patch(url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
        get_klass.delete(url: url, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.upload(origin:, url:, headers: nil, body:, expect:, conn_options: nil)
        get_klass.upload(origin: origin, url: url, headers: headers, body: body, expect: expect, conn_options: conn_options)
      end

      def self.post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        get_klass.post_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        get_klass.put_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        get_klass.patch_file(uri: uri, to: to, headers: headers, expect: expect, conn_options: conn_options)
      end

      def self.test (owner:, output:)

        http = SP::Job::HttpClient.new(owner: owner, headers:{}, mandatory_headers:[])

        puts "--- --- --- --- --- --- --- --- --- ---"
        puts "#{get_klass.name()} ~~ RUNNING ~~".purple
        puts "--- --- --- --- --- --- --- --- --- ---"

        error_count = 0

        conn_options = {}

        error_count+= self.run_test(verb: "HEAD", output: output) do
          http.head(url: 'https://httpbin.org',
            headers: {
                'Accept' => 'text/html'
            },
            expect: {
                code: 200,
                content: {
                  type: 'text/html; charset=utf-8'
                }
            },
            conn_options: conn_options
          )
        end

        error_count+= self.run_test(verb: "GET", output: output) do
          http.get(url: 'https://httpbin.org/get',
            headers: {
                'Accept' => 'application/json'
            },
            expect: {
                code: 200,
                content: {
                  type: 'application/json'
                }
            },
            conn_options: conn_options
          )
        end

        error_count+= self.run_test(verb: "POST", output: output) do
          http.post(url: 'https://httpbin.org/post',
            headers: {
                'Accept' => 'application/json',
                'Content-Type' => 'application/text'
            },
            body: '<insert POST body here>',
            expect: {
                code: 200,
                content: {
                  type: 'application/json'
                }
            },
            conn_options: conn_options
          )
        end

        error_count+= self.run_test(verb: "PUT", output: output) do
          http.put(url: 'https://httpbin.org/put',
            headers: {
                'Accept' => 'application/json',
                'Content-Type' => 'application/text'
            },
            body: '<insert PUT body here>',
            expect: {
                code: 200,
                content: {
                  type: 'application/json'
                }
            },
            conn_options: conn_options
          )
        end

        error_count+= self.run_test(verb: "PATCH", output: output) do
          http.patch(url: 'https://httpbin.org/patch',
            headers: {
              'Accept' => 'application/json',
              'Content-Type' => 'application/text'
            },
            body: '<insert PATCH body here>',
            expect: {
              code: 200,
              content: {
                type: 'application/json'
              }
            },
            conn_options: conn_options
          )
        end

        error_count+= self.run_test(verb: "DELETE", output: output) do
          http.delete(url: 'https://httpbin.org/delete',
            headers: {
              'Accept' => 'application/json'
            },
            expect: {
              code: 200,
              content: {
                type: 'application/json'
              }
            },
            conn_options: conn_options
          )
        end

        puts "--- --- --- --- --- --- --- --- --- ---"
        print "#{get_klass.name()}".purple
        print " ~~ %s ~~" % [error_count > 0 ? 'FAILED'.red : 'PASS'.green]
        print "\n"
        puts "--- --- --- --- --- --- --- --- --- ---"

      end

      private

      def self.run_test(verb:, output:, &callback)

        print "%-8s - ...".cyan % [verb]
        begin
          response = yield
          print "\r"
          $stdout.flush
          print "%-8s - PASS\n".green % [verb]
        rescue Exception => e
          response = e
          print "\r"
          $stdout.flush
          print "%-8s - FAILED\n".red % [verb]
        end

        # output response?
        if false == response.is_a?(Hash)
          if true == ( output[:on_failure] || true )
            if response.message
              puts "#{response.message}".red
            end
            ap response.backtrace
          end
          return 1
        elsif true == ( output[:on_success] || false )
          ap response.except(:body)
          if response[:body]
            begin
              ap JSON.parse(response[:body], symbolize_keys: true)
            rescue
              ap response[:body]
            end
          end
        end

        # done
        return 0

      end

    end
  end
end
