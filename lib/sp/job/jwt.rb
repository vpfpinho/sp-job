#
# Helper to obtain tokens to access toconline API's.
#
# And this is the mix-in we'll apply to Job execution classes
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

require 'jwt' # https://github.com/jwt/ruby-jwt

module SP
  module Job
  	class JWTHelper

		# encode & sign jwt
		def self.encode(key:, payload:)
			rsa_private = OpenSSL::PKey::RSA.new( File.read( key ) )
			return JWT.encode payload, rsa_private, 'RS256', { :typ => "JWT" }
		end #self.encodeJWT

    end # end class 'JWT'
  end # module Job
end# module SP
