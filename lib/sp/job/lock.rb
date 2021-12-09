# coding: utf-8
#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
#
# This file is part of sp-job.
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
require 'thread'

module SP
  module Job
    module Lock

      class Exception < StandardError

        attr_accessor :status_code
        attr_accessor :content_type
        attr_accessor :body

        def initialize(status_code:, content_type: nil, body: nil)
          @status_code  = status_code
          @content_type = content_type
          @body         = body
        end

      end # class Exception

      def exclusive_lock(key:, entity: true, entity_id: nil, user: false, user_id: nil, actions: nil, timeout: nil, message: nil, cleanup: true)
        raise 'No key'             if key.nil?
        raise 'No entity id'       if entity && entity_id.nil?
        raise 'No user id'         if user && user_id.nil?
        raise 'No timeout defined' if timeout.nil?

        Thread.current[:lock_data] ||= { lock_keys: [] }

        # get key for asked lock
        [actions || 'full_lock'].flatten.each do |action|
          # check if the key already exists on redis
          Thread.current[:lock_data][:lock_keys] << redis_lock_key(key, entity_id, action, user_id, message, timeout)
        end

        Thread.current[:lock_data][:lock_keys]
      end

      def exclusive_unlock(key:, entity: true, entity_id: nil, user: false, user_id: nil, actions: nil)
        raise 'No key'       if key.nil?
        raise 'No entity id' if entity && entity_id.nil?
        raise 'No user id'   if user && user_id.nil?

        # iterate keys to unlock
        [actions || 'full_lock'].flatten.each do |action|
          exclusive_unlock(get_redis_lock_key(key, entity_id, action, user_id))
        end
      end

      def exclusive_unlock(lock_key)
        $redis.del(lock_key)
      end

      private

      def redis_lock_key(key, entity_id, action, user_id, message, timeout)
        _lock_key = get_redis_lock_key(key, entity_id, action, user_id)

        # if lock was set then no job was running, set expire. else return false
        if !get_exclusive_redis_lock(_lock_key, timeout)
          raise ::SP::Job::Lock::Exception.new(status_code: 500, body: message)
        end
        _lock_key
      end

      def get_exclusive_redis_lock(lock_key, timeout)
        lock = $redis.setnx(lock_key, "{\"end_time\": #{expiration_time_for_exclusive_lock(timeout)}}")
        $redis.expire(lock_key, timeout)
        lock
      end

      def expiration_time_for_exclusive_lock(timeout)
        clock = Time.now + timeout
        %Q[ "#{clock.hour}:#{sprintf('%02i', (clock.min))}" ]
      end

      def get_redis_lock_key(key, entity_id, action, user_id)
        _lock_key = "#{$config[:service_id]}:exclusive-lock:#{key}"

        _lock_key = "#{_lock_key}:#{entity_id}" if entity_id
        _lock_key = "#{_lock_key}:#{user_id}"   if !user_id.nil?
        _lock_key = "#{_lock_key}:#{action}"    if !action.nil?

        _lock_key
      end

      def release_locks
        return if Thread.current[:lock_data].nil? || Thread.current[:lock_data][:lock_keys].nil?
        Thread.current[:lock_data][:lock_keys].each do |key|
          exclusive_unlock(key)
        end
      end

    end
  end
end