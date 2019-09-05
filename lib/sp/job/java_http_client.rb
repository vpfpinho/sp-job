#
# encoding: utf-8
#
# Copyright (c) 2011-2019 Cloudware S.A. All rights reserved.
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

#
# A helper class to do HTTP request without session management.
#

require 'java'

require_relative '../../../jruby/lib/sp-job.jar'

require_relative 'easy_http_client'

require 'awesome_print'

module SP
  module Job

    class JavaHTTPClient < EasyHttpClient

        #
        # Perform an HTTP HEAD request
        #
        def self.head(url:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'HEAD', url: url) do
                raise_if_not_expected(method: 'HEAD', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().head(url, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end # method 'get'
        #
        # Perform an HTTP GET request
        #
        def self.get(url:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'GET', url: url) do
                raise_if_not_expected(method: 'GET', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().get(url, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end # method 'get'

        #
        # Perform an HTTP POST request
        #
        def self.post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
            response = call(method: 'POST', url: url) do
                raise_if_not_expected(method: 'POST', url: url, response: normalize_response(response:
                    ::Java::pt.cloudware.sp.job.HTTPClient.new().post(url, headers, body,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end # method 'post'

        #
        # Perform an HTTP PUT request
        #
        def self.put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
            response = call(method: 'PUT', url: url) do
                raise_if_not_expected(method: 'PUT', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().put(url, headers, body,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end # method 'put'

        #
        # Perform an HTTP PATCH request
        #
        def self.patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
            response = call(method: 'PATCH', url: url) do
                raise_if_not_expected(method: 'PATCH', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().patch(url, headers, body,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end # method 'patch'

        #
        # Perform an HTTP DELETE request
        #
        def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'DELETE', url: url) do
                raise_if_not_expected(method: 'DELETE', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().delete(url, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
             )
            end
        end # method 'delete'

        #
        # Perform an HTTP GET request to obtain a file
        #
        def self.get_to_file(url:, to:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'GET', url: url) do
                raise_if_not_expected(method: 'GET', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().get_to_file(url, headers, to,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end

        #
        # Perform an HTTP POST and write response to file
        #
        def self.post_to_file(url:, headers: nil, body:, to:, expect: nil, conn_options: nil)
            response = call(method: 'POST', url: to) do
                raise_if_not_expected(method: 'POST', url: url, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().post_to_file(url, headers, body, to,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end

        #
        # Perform an HTTP POST request to send a file
        #
        def self.post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'POST', url: to, local_file_uri: uri) do
                raise_if_not_expected(method: 'POST', url: to, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().post_file(uri, to, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end

        #
        # Perform an HTTP PUT request to send a file
        #
        def self.put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'PUT', url: to, local_file_uri: uri) do
                raise_if_not_expected(method: 'PUT', url: to, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().put_file(uri, to, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end

        #
        # Perform an HTTP PATCH request to send a file
        #
        def self.patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
            response = call(method: 'PATCH', url: to, local_file_uri: uri) do
                raise_if_not_expected(method: 'PATCH', url: to, response: normalize_response(response:
                        ::Java::pt.cloudware.sp.job.HTTPClient.new().patch_file(uri, to, headers,
                            expect_hash_to_object(expect: expect),
                            connection_hash_to_object(options: conn_options)
                        )
                    ),
                    expect: expect
                )
            end
        end

        private

        #
        #
        #
        def self.expect_hash_to_object(expect:)
            if nil == expect
                return nil
            end
            if expect[:content]
                content = ::Java::pt.cloudware.sp.job.HTTPClient::Expect::Content.new(
                    expect[:content][:type]
                )
            else
                content = nil
            end
            return ::Java::pt.cloudware.sp.job.HTTPClient::Expect.new(
                expect[:code],
                content
            )
        end

        #
        #
        #
        def self.connection_hash_to_object(options:)
            if nil != options
                ::Java::pt.cloudware.sp.job.HTTPClient::Connection.new(
                    ::Java::pt.cloudware.sp.job.HTTPClient::Connection::Timeouts.new(
                        options[:connection_timeout], options[:request_timeout]
                    )
                )
            else
                nil
            end
        end # 'self.self.connection_hash_to_object'

        #
        # Normalize JAVA response
        #
        # @param response
        #
        def self.normalize_response(response:)
            rv =  {
                    code: response.code,
                    body: response.body,
                    description: http_reason(code: response.code),
            }
            if nil != response.content
                return rv.merge(
                        content: {
                            type: response.content.type,
                            length: response.content.length
                    }
                )
            else
                return rv
            end
        end # 'self.normalize_response'

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
        rescue Java::JavaIo::FileNotFoundException
          raise ::SP::Job::EasyHttpClient::SourceFileNotFound.new(method: method, url: url, local_file_uri: local_file_uri)        
        end
        response
      end # 'self.call'

    end # class 'JavaHTTPClient'

  end # module 'Job'
end # module 'SP'
