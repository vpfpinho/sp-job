#!/usr/bin/env ruby
#
# encoding: utf-8
#
# Copyright (c) 2018 Cloudware S.A. Allrights reserved
#
# Helper to obtain tokens to access toconline API's.
#

require 'jwt' # https://github.com/jwt/ruby-jwt

module SP
  module Job
  	class JWT

		# encode & sign jwt
		def self.encode(key:, payload:)
			rsa_private = OpenSSL::PKey::RSA.new( File.read( key ) )
			return JWT.encode payload, rsa_private, 'RS256', { :typ => "JWT" }
		end #self.encodeJWT

    end # end class 'JWT'
  end # module Job
end# module SP
