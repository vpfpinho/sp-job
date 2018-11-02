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
# Helper class to create simplifed OAUTH sessions suitable for jobs and casper applications, for the full blown OAUTH scene check casper-nginx-broker
#

module SP
  module Job

    class Session

      attr_reader :access_ttl
      attr_reader :refresh_ttl

      def initialize (configuration:, serviceId:, multithread: false, programName:, redis:)
        @sid           = serviceId
        @access_ttl    = configuration[:oauth2][:access_ttl]  || (1 * 3600)  # Duration of the access tokens
        @refresh_ttl   = configuration[:oauth2][:refresh_ttl] || (2 * 3600)  # Duration of the refresh tokens
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
      # Create a brand new access token with optional refresh token
      #
      # @param patch symbolicated hash with session data
      # @param with_refresh when true the refresh token is also created, when false just access
      # @return access_token or access_token and refresh token
      #
      def create (patch:, with_refresh: false)
        session = patch.merge(@session_base)
        session[:created_at] = Time.new.iso8601
        if with_refresh
          refresh_token = create_token(session: session, refresh_token: true)
          session[:refresh_token] = refresh_token
        else
          session.delete(:refresh_token)
          refresh_token = nil
        end
        access_token = create_token(session: session)
        return access_token, refresh_token
      end

      #
      # Create an access token by clonning a refresh token
      #
      # @param refresh_token the id of the refresh token
      # @param session symbolicated session data
      #
      def create_from_refresh (refresh_token:, session:)
        session[:created_at] = Time.new.iso8601
        session[:refresh_token] = refresh_token
        return create_token(session: session)
      end

      #
      # Retrieve session hash from redis, keys are symbolicated
      #
      # @param token The access or refresh token
      # @param refresh true for refresh, false for access_token
      #
      def get (token:, refresh: false)
        key = "#{@sid}:oauth:#{refresh ? 'refresh_token' : 'access_token'}:#{token}"
        session = nil
        redis do |r|
          session = r.hgetall(key)
        end
        rv = Hash.new
        session.each do |key,value|
          rv[key.to_sym] = value
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
        refresh_token = session[:refresh_token]
        patch.each do |key, value|
          if value.nil?
            session.delete(key)
          else
            session[key] = value
          end
        end
        at, rt = create(patch: session, with_refresh: refresh_token != nil)
        dispose(token: token, refresh_token: refresh_token)
        return at,rt
      end

      #
      # Cross patch, creates a new token on the current cluster by patching a source token from another cluster
      #
      # @param source session handler from which the original token is read
      # @param token id of the original token on the source cluster
      # @param patch symbolicated hash that is fused into source cluster
      # @return fresh pait of access_token and refresh_token
      #
      def x_patch (source:, token:, patch:)
        session = source.get(token: token)
        refresh_token = session[:refresh_token]
        patch.each do |key, value|
          if value.nil?
            session.delete(key)
          else
            session[key] = value
          end
        end
        at, rt = create(patch: session, with_refresh: refresh_token != nil)
        source.dispose(token: token, refresh_token: refresh_token)
        return at,rt
      end

      #
      # Delete tokens, immediately or after a grace period.
      #
      # @param token access token to dispose
      # @param refresh_token (optional) refresh token to dispose
      # @param timeleft grace period to keep the token alive, 0 to dispose immediately
      #
      # @note if the refresh token is not supplied attempts to retrive it from the access token
      #
      def dispose (token:, refresh_token: nil, timeleft: nil)
        timeleft ||= @tolerance_ttl
        key = "#{@sid}:oauth:access_token:#{token}"
        redis do |r|
          if refresh_token.to_s.size == 0
            refresh_token = r.hget(key, 'refresh_token')
          end
          if refresh_token.to_s.size != 0
            rkey = "#{@sid}:oauth:refresh_token:#{refresh_token}"
            r.expire(rkey, timeleft)
          end
          r.expire(key, timeleft)
        end
      end

      #
      # Extend the life of a token by timetolive seconds
      #
      # @param token the token to preserve
      # @param refresh true it's a refresh token, false for access
      # @param timetolive new duration in seconds
      #
      def extend (token:, refresh: false, timetolive:)
        key = "#{@sid}:oauth:#{refresh ? 'refresh_token' : 'access_token'}:#{token}"
        rv  = 0
        redis do |r|
          rv = r.expire(key, timetolive)
        end
        return rv
      end

      protected

      def create_token (session:, refresh_token: false)
        token = nil
        3.times do
          token = SecureRandom.hex(32)
          key = "#{@sid}:oauth:#{refresh_token ? 'refresh_token' : 'access_token'}:#{token}"
          hset = []
          session.each do |key, value|
            unless value.nil?
              hset << key
              hset << value.to_s
            end
          end
          redis do |r|
            unless r.exists(key)
              r.pipelined do
                r.hmset(key, hset)
                r.expire(key, refresh_token ? @refresh_ttl : @access_ttl)
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
