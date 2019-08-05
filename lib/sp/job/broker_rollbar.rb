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

require 'sp/job/easy_http_client'

module SP
    module Job

        class BrokerRollbar
            extend SP::Job::Common
            
            
            # {
            # 	"agent": "nginx-broker v1.3.53fs",
            # 	"module": "cdn",
            # 	"title": null,
            # 	"payload": {},
            # 	"type": "error",
            # 	"code": 500
            # }

            def self.perform(job)

                title = title || "#{job[:agent]} // #{job[:module].upcase} // #{job[:code]} - #{EasyHttpClient.http_reason(code: job[:code])}"

                payload = job.delete_if { |k, v| v.nil? }

                case job[:type]
                when 'info'
                    Rollbar.info(title, job)
                when 'warning'
                    Rollbar.warning(title, job)
                when 'critical'
                    Rollbar.critical(title, job)
                else
                    Rollbar.error(title, job)
                end

            end # 'self.perform'

        end # class 'BrokerRollbar'

    end # module 'Job'
end # end module 'SP'