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

        class BrokerArchiveClient

            #
            # @param url
            # @param ownder
            #            
            def initialize(url:, owner:)
                @url  = url
                @http = ::SP::Job::HttpClient.new(owner: owner)
            end

            #
            # Perform an HTTP POST request to upload a file
            #
            # @param uri
            # @param headers
            # @param expect
            # @param conn_options
            #
            def post(uri:, headers: nil, expect: nil, conn_options: nil)
                @http.post_file(uri: uri, to: @url, headers: headers, expect: expect, conn_options: conn_options)
            end

        end     

    end # module 'Job'
end # module 'SP'