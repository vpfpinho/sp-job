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
    # Perform an HTTP GET request
    #
    # @param url
    # @param headers
    # @param expect
    # @param conn_options
    #
    def self.head(url:, headers: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
            ::Java::pt.cloudware.sp.job.HTTPClient.new().head(url, headers,
                expect_hash_to_object(expect: expect),
                connection_hash_to_object(options: conn_options)
            )
        ),
        expect: expect
    )
    end # method 'get'
    #
    # Perform an HTTP GET request
    #
    # @param url
    # @param headers
    # @param expect
    # @param conn_options
    #
    def self.get(url:, headers: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
                ::Java::pt.cloudware.sp.job.HTTPClient.new().get(url, headers,
                    expect_hash_to_object(expect: expect),
                    connection_hash_to_object(options: conn_options)
                )
            ),
            expect: expect
        )
    end # method 'get'

    #
    # Perform an HTTP POST request
    #
    # @param url
    # @param headers
    # @param body
    # @param expect
    # @param conn_options
    #
    def self.post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
              ::Java::pt.cloudware.sp.job.HTTPClient.new().post(url, headers, body,
                    expect_hash_to_object(expect: expect),
                    connection_hash_to_object(options: conn_options)
                )
            ),
            expect: expect
        )
    end # method 'post'

    #
    # Perform an HTTP PUT request
    #
    # @param url
    # @param headers
    # @param body
    # @param expect
    # @param conn_options
    #
    def self.put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
                ::Java::pt.cloudware.sp.job.HTTPClient.new().put(url, headers, body,
                    expect_hash_to_object(expect: expect),
                    connection_hash_to_object(options: conn_options)
                )
            ),
            expect: expect
        )
    end # method 'put'

    #
    # Perform an HTTP PATCH request
    #
    # @param url
    # @param headers
    # @param body
    # @param expect
    # @param conn_options
    #
    def self.patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
                ::Java::pt.cloudware.sp.job.HTTPClient.new().patch(url, headers, body,
                    expect_hash_to_object(expect: expect),
                    connection_hash_to_object(options: conn_options)
                )
            ),
            expect: expect
        )
    end # method 'patch'

    #
    # Perform an HTTP DELETE request
    #
    # @param url
    # @param headers
    # @param expect
    # @param conn_options
    #
    def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
        raise_if_not_expected(response: normalize_response(response:
                ::Java::pt.cloudware.sp.job.HTTPClient.new().delete(url, headers,
                    expect_hash_to_object(expect: expect),
                    connection_hash_to_object(options: conn_options)
                )
            ),
            expect: expect
        )
    end # method 'delete'

    private

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
    end

    #
    # Normalize JAVA response
    #
    # @param response
    #
    def self.normalize_response(response:)
        {
            code: response.code,
            body: response.body,
            description: http_reason(code: response.code),
            content: {
                type: response.content.type,
                length: response.content.length
            }
        }
    end

    end # class 'JavaHTTPClient'

  end # module 'Job'
end # module 'SP'