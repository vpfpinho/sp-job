#
# Copyright (c) 2011-2020 Cloudware S.A. All rights reserved.
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

class EmailValidate
  extend SP::Job::Common
    
  @@tube_options = { simpleapi: true }
    
  def self.tube_options
    @@tube_options
  end
      
  #
  # Uses regex and DNS MX record query to validate an email domain
  #
  # @param job the only key required is :urn with an email parameter
  # @return json api faked response
  #
  def self.perform (job)
      
    # disassemble the URN ..
    uri    = URI(job[:urn])
    params = URI::decode_www_form(uri.query).to_h
    email  = params['email']

    # ... Validate! ...
    valid  = email_address_valid?(email)
    if valid 
      logger.info "-- email #{email} is valid".cyan
    else
      logger.info "-- email #{email} is *NOT* valid".yellow
    end

    # ... send response 
    # TODO morph this to be simpler on casper socket jget
    send_response(response: { 
      data: {
        id: '0', 
        type: 'email-validate', 
        attributes: { 
          valid: valid, 
          email: email 
        }
      }
    })
    
  end
    
end