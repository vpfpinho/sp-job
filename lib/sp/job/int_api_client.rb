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

require 'sp/job/http_client'

module SP
  module Job
    class IntApiClient < HttpClient
      attr_accessor :url

      def initialize(owner:, url:, headers: {}, x_casper_values: {})
        __headers = headers
        x_casper_values.each do | k, v |
          __headers["X-CASPER-#{k.to_s.gsub('_', '-').upcase}"] = v
        end


        mandatory_headers = [
          'X-CASPER-ENTITY-ID',
          'X-CASPER-ROLE-MASK',
          'X-CASPER-USER-ID',
          'X-CASPER-USER-EMAIL'
        ]

        super(
          owner: owner,
          headers: __headers,
          mandatory_headers: (mandatory_headers + __headers.keys).uniq
        )

        @url = url
      end
    end
  end
end
