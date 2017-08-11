#
# Copyright (c) 2011-2016 Servicepartner LDA. All rights reserved.
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

module SP
	module Job

		#
    # Beanstalk job that performs a login @ nginx-broker and obtains a new session
    #
    class BrokerLogin < BeanRunner

 			def process (job)
 				byebug
				sign_in(job[:email], job[:password])
 				new_session(job[:scope], job[:redirect_uri])
 			end

	    def sign_in (a_email, a_password)
	    end

	    def sign_out ()
	    end

	    def extend ()
	    end

 			#
 			# Generate an access code and call redirect URI.
 			#
 			def authorization_code_fetch_and_callback(a_scope, a_redirect_uri)
 				client = ::Sp::BrokerOAuth2Client.new(@@config[:oauth2][:host], @@config[:oauth2][:client][:id], @@config[:oauth2][:secret])
 				client.do_call_authorization_url({
 					:redirect_uri => a_redirect_uri,
 					:scope => a_scope
 				})
 			end

 			#
 			# Generate a new session - [ access_token and refresh_token ].
 			#
 			def new_session (a_scope, a_redirect_uri)

 				client = ::Sp::BrokerOAuth2Client.new(@@config[:oauth2][:host], @@config[:oauth2][:client][:id], @@config[:oauth2][:secret])
 				ac_response = client.do_get_authorization_code({
 					:redirect_uri => a_redirect_uri,
 					:scope => a_scope
 				})
 				at_response = client.do_exchange_auth_code_for_token(
 					:params => {
 						:code => "#{ac_response[:oauth2][:code]}",
 						:redirect_uri => a_redirect_uri
 				})

 				puts "access_token=", at_response[:access_token]
 				puts "refresh_token=", at_response[:refresh_token]

 			end

    end # class

  end # module 'Job'
end # module 'Sp'
