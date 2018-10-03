#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
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
        @access_ttl    = 6 * 3600 # TODO read from redadis conf
        @refresh_ttl   = 400
        @tolerance_ttl = 120 # Time a deleted token will remain "alive"
        @redis         = redis
        @session_base  = {
          patched_by:   programName,
          client_id:    configuration[:oauth2][:client_id],
          redirect_uri: configuration[:oauth2][:redirect_uri],
          scope:        configuration[:oauth2][:scope],
          issuer:       programName,
          on_refresh_issue_new_pair: true
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

      def create (patch:, with_refresh: false)
        if with_refresh
          refresh_token = create_token(patch: patch, refresh_token: true)
          patch[:refresh_token] = refresh_token
        else
          patch.delete(:refresh_token)
          refresh_token = nil
        end
        access_token = create_token(patch: patch)
        return access_token, refresh_token
      end

      def get (token:)
        key = "#{@sid}:oauth:access_token:#{token}"
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

      def patch (token:, patch:)
        session = get(token: token)
        patch.each do |key, value|
          if value.nil?
            session.delete(key)
          else
            session[key] = value
          end
        end
        at, rt = create_token(patch: session)
        dispose(:token token)
        return at,rt
      end

      def dispose (token:, timeleft: nil)
        timeleft ||= @tolerance_ttl
        key = "#{@sid}:oauth:access_token:#{token}"
        redis do |r|
          r.expire(key, timeleft)
        end
      end

      protected

      def create_token (patch:, refresh_token: false)
        session = patch.merge(@session_base)
        session[:created_at] = Time.new.iso8601
        token = nil
        3.times do
          token = SecureRandom.hex(32)
          key = "#{@sid}:oauth:#{refresh_token ? 'refresh_token' : 'access_token'}:#{token}"
          redis do |r|
            unless r.exists(key)
              r.pipelined do
                r.hmset(key, session.flatten.map{|e| e.to_s })
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