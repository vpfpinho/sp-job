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
# encoding: utf-8
#

require 'sp/job/int_api_client'

module SP
  module Job

    SP::Job::ROLE_IS_JOB = 0x40000000

    class CentralApiClient < SP::Job::IntApiClient

      def initialize(owner:, url:, job:)
        super(
          owner: owner,
          url:   url,
          headers: { 'Content-Type' => 'application/json', 'Accept' => 'application/json' },
          x_casper_values: {
            entity_id:  job[:entity_id],
            role_mask: (job[:role_mask].to_i | SP::Job::ROLE_IS_JOB),
            user_id:    job[:user_id],
            user_email: job[:user_email],
          }
        )
        @job = job.dup
      end

      def set(job:)
        reset(headers: { 'Content-Type' => 'application/json', 'Accept' => 'application/json' },
              x_casper_values: {
                entity_id:  job[:entity_id],
                role_mask: (job[:role_mask].to_i | SP::Job::ROLE_IS_JOB),
                user_id:    job[:user_id],
                user_email: job[:user_email],
              }
        )
        @job = job.dup
      end

      def head(path)
        return __parse(super(url: @url + path, headers: @headers))
      end

      def get(path)
        return __parse(super(url: @url + path, headers: @headers))
      end

      def post(path, body)
        return __parse(super(url: @url + path, body: body.to_json, headers: @headers, expect: nil))
      end

      def put(path, body)
        return __parse(super(url: @url + path, body: body.to_json, headers: @headers, expect: nil))
      end

      def patch(path, body)
        return __parse(super(url: @url + path, body: body.to_json, headers: @headers, expect: nil))
      end

      def delete(path)
        return __parse(super(url: @url + path, headers: @headers, expect: nil))
      end

      private

      def __parse(response)
        case response[:code]
        when 200
          return JSON.parse(response[:body], :symbolize_names => true)
        when 201,204
          return true
        else
          begin
            error = JSON.parse(response[:body], :symbolize_names => true)[:error]
          rescue => e
            error = 'Unknown error'
          end
          raise SP::Job::HttpClient::StandardError.new(code: response[:code], message: error)
        end
      end

    end

  end # job
end # sp
