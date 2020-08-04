#
# Copyright (c) 2017-2018 Cloudware S.A. All rights reserved.
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
# Helper class to create simplifed sessions suitable for jobs and casper applications, for a full blown OAUTH scene check casper-nginx-broker
#

module SP
  module Job

    class Session

      attr_reader :access_ttl

      def initialize (configuration:, multithread: false, programName:, redis:)
        @sid           = configuration[:service_id]
        @@sid          = @sid
        @access_ttl    = configuration[:oauth2][:access_ttl]  || (1 * 3600)  # Duration of the access tokens
        @tolerance_ttl = configuration[:oauth2][:deleted_ttl] || 30          # Time a deleted token will remain "alive"
        @redis         = redis
        @session_base  = {
          patched_by:   programName,
          client_id:    configuration[:oauth2][:client_id],
          redirect_uri: configuration[:oauth2][:redirect_uri],
          scope:        configuration[:oauth2][:scope],
          issuer:       programName
        }

        if multithread
          raise 'Multithreading is not supported in MRI/CRuby' unless RUBY_ENGINE == 'jruby'
          @redis_mutex = Mutex.new
        else
          @redis_mutex = nil
        end
      end

      #
      # Thread safe redis driver, pass a block to execute a generic redis operation
      #
      def redis
        # callback is not optional
        if @redis_mutex.nil?
          yield(@redis)
        else
          # ... to enforce safe usage!
          @redis_mutex.synchronize {
            yield(@redis)
          }
        end
      end

      #
      # Create a brand new access token 
      #
      # @param patch symbolicated hash with session data
      # @return access_token or access_token
      #
      def create (patch:, duration: nil)
        session = patch.merge(@session_base)
        session[:created_at] = Time.new.iso8601
        access_token = create_token(session: session, duration: duration)
        return access_token
      end

      #
      # Return the redis key used for the given access token 
      #
      def self.tokenToKey (token) 
        "#{@@sid}:oauth:access_token:#{token}"
      end

      #
      # Extract ids from the token
      #
      def self.tokenToIds (token)
        idx = token.indexOf('_token:')
        if idx.nil?
          ['0','0','0','']
        else
          token[idx..-1].split('-')
        end
      end

      #
      # Retrieve session hash from redis, keys are symbolicated
      #
      # @param token The access token
      #
      def get (token:)
        key = "#{@sid}:oauth:access_token:#{token}"
        session = nil
        redis do |r|
          session = r.hgetall(key)
        end
        rv = Hash.new
        session.each do |_key,value|
          rv[_key.to_sym] = value
        end
        return rv
      end

      #
      # Create a token pair session by merging an existing access_token with the given patch
      #
      # @param token The access token to retrieve the original session hash
      # @param patch a symbolicated hash that will overide existing keys and/or add new ones
      #
      # @note Use null values on the patch to delete keys from the original session
      #
      def patch (token:, patch:)
        session = get(token: token)
        patch.each do |key, value|
          if value.nil?
            session.delete(key)
          else
            session[key] = value
          end
        end
        at = create(patch: session)
        dispose(token: token)
        return at
      end

      #
      # Create a token pair session by merging an existing session with the given patch
      #
      # @param session the original session hash
      # @param patch a symbolicated hash that will overide existing keys and/or add new ones
      #
      # @note Use null values on the patch to delete keys from the original session
      #
      def merge (session:, patch:, duration: nil)
        patch.each do |key, value|
          if value.nil?
            session.delete(key)
          else
            session[key] = value
          end
        end
        return create(patch: session, duration: duration)
      end

      #
      # Delete tokens, immediately or after a grace period.
      #
      # @param token access token to dispose
      # @param timeleft grace period to keep the token alive, 0 to dispose immediately
      #
      def dispose (token:, timeleft: nil)
        key = "#{@sid}:oauth:access_token:#{token}"
        redis do |r|
          r.expire(key, timeleft || @tolerance_ttl)
        end
      end      
      
      #
      # Extend the life of a token by timetolive seconds
      #
      # @param token the token to preserve
      # @param timetolive new duration in seconds
      #
      def extend (token:, timetolive: nil) 
        key = "#{@sid}:oauth:access_token:#{token}"
        rv  = 0
        redis do |r|
          rv = r.expire(key, timetolive || @access_ttl)
        end
        return rv
      end

      #
      # Check if a token exists
      #
      # @param token the token to check
      #
      def exists (token) 
        redis do |r|
          r.exists("#{@sid}:oauth:access_token:#{token}")
        end
      end

      protected

      def create_token (session:, duration: nil)
        token = nil
        5.times do
          token = "#{session[:cluster]}-#{session[:entity_id].to_i}-#{session[:user_id]}-#{SecureRandom.hex(32)}"
          key = "#{@sid}:oauth:access_token:#{token}"
          hset = []
          session.each do |_key, value|
            unless value.nil?
              hset << _key
              hset << value.to_s
            end
          end
          redis do |r|
            unless r.exists(key)
              r.pipelined do
                r.hmset(key, hset)
                if duration.nil?
                  r.expire(key, @access_ttl)
                else
                  r.expire(key, duration)
                end
              end
              return token
            end
          end
        end
        return nil
      end

    end

  end
end
