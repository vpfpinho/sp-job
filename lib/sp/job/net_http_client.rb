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

# require 'net/http'
# require 'uri'

module SP
  module Job
    class NetHTTPClient
      extend ::SP::Job::HttpStatusCode

      def self.post(url:, headers:, body:, expect:)
        # uri = URI.parse(url)
        # http = Net::HTTP.new(uri.host, uri.port)
        #
        # request = Net::HTTP::Post.new(uri.request_uri)
        # request.body = body
        #
        # headers.each do |k,v|
        #   request[k] = v
        # end
        #
        # r = http.request(request)
        #
        # nr = self.normalize_response(response: r)
        # # compare status code
        # if nr[:code] != expect[:code]
        #   if 401 == nr[:code]
        #     raise ::SP::Job::JSONAPI::Error.new(status: nr[:code], code: 'A01', detail: nil)
        #   else
        #     raise ::SP::Job::JSONAPI::Error.new(status: nr[:code], code: 'B01', detail: nil)
        #   end
        # end
        # # compare content-type
        # if nr[:content][:type] != expect[:content][:type]
        #   raise ::SP::Job::JSONAPI::Error.new(status: 500, code: 'I01', detail: "Unexpected 'Content-Type': #{nr[:content][:type]}, expected #{expect[:content][:type]}!")
        # end
        # # done
        # nr
        client = Manticore::Client.new
        response = client.post(url, body: body, headers: headers)


        ap response.code
        ap response.body
        ap response.headers
        nil
      end

      private

      def self.normalize_response(response:)
        o = {
          code: response.code.to_i,
          body: response.body,
          description: self.http_reason(code: response.code.to_i),
          content: {
            type: nil,
            length: 0
          }
        }

        response.header.each_header do |key, value|
          case key
          when 'content-type'
            o[:content][:type] = value
          when 'content-length'
            o[:content][:length] = value
          end
        end

        o
      end


    end
  end
end
