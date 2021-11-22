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

      # key: Path of the private key to be used on encoding
      # jwt_validity: Must be set in hours, how long the JWT will last
      # tube: Name of the tube
      # ttr: Job max execution time in seconds
      # validity: max time the job can wait in queue before starting
      # payload: Data to be used on the job
      def self.jobify(key:, jwt_validity: 24, tube:, ttr: 8600, validity: 180, payload:)
        # UTC timestamp
        now        = Time.now.getutc.to_i
        # Expire
        exp_offset = jwt_validity * 60 * 60
        exp        = now + exp_offset
        # Issued At
        iat        = now
        # Not before
        nbf        = now

        job_payload = { tube: tube }
        job_payload.merge!(payload)

        self.encode(key: key, payload: {
          action: 'job',
          exp: exp, # Data de expiração
          iat: iat, # Issued at
          nbf: nbf, # Not before
          job: {
            tube: tube,
            ttr: ttr,
            validity: validity,
            payload: job_payload
          }
        })
      end

      def self.validate(public_key:, jwt:)
        JWT.decode(
          jwt,
          public_key,
          true,
          algorithms: 'RS256',
          verify_iss: true,
        )
      end

      # Submit a jwt for a job
      def self.submit (url:, jwt:, expect: { code: 200, content: { type: 'application/json' }})
        response = HttpClient.get_klass.post(
          url: url,
          headers: {
            'Content-Type' => 'application/text'
          },
          body: jwt,
          expect: expect
        )
        response
      end

    end # end class 'JWT'
  end # module Job
end# module SP
