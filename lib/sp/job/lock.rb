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

      class DefinedLocks
        ACCOUNTING = 'accounting'

        def self.get_locks
          [ ::SP::Job::Lock::DefinedLocks::ACCOUNTING ]
        end
      end

      class Placeholder
        EMAIL      = 'email'
        USERNAME   = 'username'
        ACTION     = 'action'
        STARTED_AT = 'started_at'
        LOCK_UNTIL = 'lock_until'

        def self.get_placeholders
          [
            ::SP::Job::Lock::Placeholder::EMAIL,
            ::SP::Job::Lock::Placeholder::USERNAME,
            ::SP::Job::Lock::Placeholder::ACTION,
            ::SP::Job::Lock::Placeholder::STARTED_AT,
            ::SP::Job::Lock::Placeholder::LOCK_UNTIL
          ]
        end
      end

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

      def exclusive_lock(key:,
                         entity: true, entity_id: nil,
                         user: false, user_id: nil, username: nil, email: nil,
                         actions: nil, timeout: nil, cleanup: true,
                         title: nil, sub_title: nil, message: nil)
        raise 'No key'              if key.nil?
        raise 'No entity id'        if entity && entity_id.nil?
        raise 'No user id'          if user && user_id.nil?
        raise 'No timeout defined'  if timeout.nil?
        raise 'No username defined' if username.nil?
        raise 'No email defined'    if email.nil?

        raise 'Invalid lock'        if !::SP::Job::Lock::DefinedLocks.get_locks.include?(key)

        begin
          Thread.current[:lock_data] ||= { lock_keys: [], generated_keys: [] }

          # get key for asked lock
          [actions || 'full_lock'].flatten.each do |action|
            # check if the key already exists on redis
            Thread.current[:lock_data][:lock_keys] << redis_lock_key(key, entity_id, action, user_id, username, email, message, timeout)
          end

          return Thread.current[:lock_data][:lock_keys]
        rescue ::SP::Job::Lock::Exception => e
          if cleanup
            report_duplicated_job(title: title, sub_title: sub_title, message: message)
          else
            raise e
          end
        end
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
        redis do |r|
          r.del(lock_key)
        end
      end

      private

      def redis_lock_key(key, entity_id, action, user_id, username, email, message, timeout)
        _lock_key = get_redis_lock_key(key, entity_id, action, user_id)
        Thread.current[:lock_data][:generated_keys] << _lock_key

        # if lock was set then no job was running, set expire. else return false
        if !get_exclusive_redis_lock(_lock_key, timeout, username, email, action)
          release_locks(_lock_key)
          raise ::SP::Job::Lock::Exception.new(status_code: 500, body: message)
        end

        _lock_key
      end

      def get_exclusive_redis_lock(lock_key, timeout, username, email, action)
        lock = nil
        redis do |r|
          lock = r.setnx(lock_key, {
            email: email,
            username: username,
            started_at: format_time(Time.now),
            lock_until: format_time(Time.now + timeout),
            action: action
          }.to_json)
          r.expire(lock_key, timeout)
        end
        lock
      end

      def expiration_time_for_exclusive_lock(timeout)
        time = Time.now + timeout
        format_time(time)
      end

      def format_time(time)
        %Q[ #{time.strftime("%d/%m/%Y %k:%M")} ]
      end

      def get_redis_lock_key(key, entity_id, action, user_id)
        _lock_key = "#{$config[:service_id]}:exclusive-lock:#{key}"

        _lock_key = "#{_lock_key}:#{entity_id}" if entity_id
        _lock_key = "#{_lock_key}:#{user_id}"   if !user_id.nil?
        _lock_key = "#{_lock_key}:#{action}"    if !action.nil?

        _lock_key
      end

      def release_locks(excape = nil)
        return if Thread.current[:lock_data].nil? || Thread.current[:lock_data][:lock_keys].nil?
        Thread.current[:lock_data][:lock_keys].each do |key|
          next if key == excape
          exclusive_unlock(key)
        end
      end

      def report_duplicated_job(title: nil, sub_title: nil, message: nil)

        notice_title     =     title || 'Tarefa duplicada'
        notice_sub_title = sub_title || 'Não é permitido realizar mais do que uma tarefa do mesmo tipo em simultâneo.'
        notice_message   =   message || 'Acompanhe a evolução da tarefa em curso na área de notificações, logo que a tarefa em curso termine poderá submeter o novo pedido'

        message = <<-HTML
          <div class="custom-message">
            <casper-icon class="error-icon" icon="fa-light:exclamation-circle"></casper-icon>
            <h2>#{replace_keys(notice_title)}</h2>
            <span>#{replace_keys(notice_sub_title)}</span>
            <div style="flex-grow: 2.0;"></div>
            <casper-notice title="Aviso" type="warning">#{replace_keys(notice_message)}</casper-notice>
          </div>
        HTML
        report_error(message: message, custom: true, response: { conflict_in_tube: true})
      end

      def replace_keys(message)
        _message = message
        _key = Thread.current[:lock_data][:generated_keys].last
        _value = nil

        redis do |r|
          _value = JSON.parse(r.get(_key))
        end

        if !_value.nil?
          ::SP::Job::Lock::Placeholder.get_placeholders.each do |keyword|
            _message = _message.gsub("${#{keyword}}", _value[keyword].to_s)
          end
        end

        _message
      end

    end
  end
end