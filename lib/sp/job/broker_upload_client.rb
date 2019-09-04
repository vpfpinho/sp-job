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

require 'fileutils'

module SP
    module Job
  
      #
      # nginx-broker 'upload' module client - [ WARNING - USAGE INTENDED ONLY FOR DEBUG / TESTING PROPOSES - WORKS ONLY WITH CURB ]
      #
      class BrokerUploadClient

        #
        # Initialize a 'upload' module client.
        #
        # @param owner [REQUIRED]Client's owner - usually tube name - used for 'User-Agent' header.
        # @param url   [REQUIRED] Base URL
        # @param job   [REQUIRED] At least must contain entity_id, user_id, role_mask and module_mask attributes.
        #            
        def initialize(owner:, url:) 
            @url = url
            @http = ::SP::Job::HttpClient.new(owner: owner, headers: {}, mandatory_headers: {})
        end

        #
        # Perform an HTTP POST request to 'Move' a previously uploaded archive.
        #
        # @param body Data to upload
        #
        # @return
        #
        # {
        #     "file": <string>
        # }
        #
        def upload(body:)            
            response = @http.upload(origin: "#{URI.parse(@url).scheme}://localhost:#{URI.parse(@url).port}", url: @url, body: body,
                expect: {
                    code: 200,
                    content: {
                        type: 'application/json'
                    }
                }
            )
            # return body only 
            JSON.parse(response[:body], symbolize_names: true)
        end

      end # class 'BrokerUploadClient'      

    end # module Job
end #module SP