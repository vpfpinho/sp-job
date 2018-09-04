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

module SP
  module Job
    class CurlHTTPClient < EasyHttpClient
      def self.post(url:, headers:, body:, expect:)
        # since we're not auto-renew tokens, we can use a simple CURL request
        r = Curl::Easy.http_post(url, body) do |handle|
          headers.each do |k,v|
            handle.headers[k] = v
          end
        end
        nr = self.normalize_response(curb_r: r)
        # compare status code
        if nr[:code] != expect[:code]
          if 401 == nr[:code]
            raise ::SP::Job::JSONAPI::Error.new(status: nr[:code], code: 'A01', detail: nil)
          else
            raise ::SP::Job::JSONAPI::Error.new(status: nr[:code], code: 'B01', detail: nil)
          end
        end
        # compare content-type
        if nr[:content][:type] != expect[:content][:type]
          raise ::SP::Job::JSONAPI::Error.new(status: 500, code: 'I01', detail: "Unexpected 'Content-Type': #{nr[:content][:type]}, expected #{expect[:content][:type]}!")
        end
        # done
        nr
      end

      def self.get(url:)
        response = Curl::Easy.http_get(url)
        self.normalize_response(curb_r: response)
      end

      private

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


    end
  end
end
