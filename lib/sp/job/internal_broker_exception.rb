#
# encoding: utf-8
#
# Copyright (c) 2011-2017 Cloudware S.A. All rights reserved.
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

require 'sp/job/broker_oauth2_client' unless 'jruby' == RUBY_ENGINE # ::SP::Job::BrokerOAuth2Client::InvalidToken

class InternalBrokerException

  def self.handle(task:, exception:, hooks:, callback:)

    response = InternalBrokerException.translate_to_response(e: exception)
    job_id   = task.id
    job_body = JSON.parse(task.body, symbolize_names: true)

    job_options = hooks[:var].invoke_hook_events(hooks[:klass], :on_raise_response_was_sent, job_id, job_body, response)
    if nil == job_options || false == job_options.is_a?(Array) || 1 != job_options.size || false == job_options[0].is_a?(Hash)
      rv = { response: response }
    else
      job_options = job_options[0]
      # rollbar it
      if true == job_options.include?(:rollbar) && true == job_options[:rollbar]
        InternalBrokerException.rollbar(job_id: job_id, job_body: job_body, exception: exception)
      end
      #
      rv = { bury: job_options[:bury] , raise: job_options[:raise], response: job_options[:response] || response }
    end

    # send response
    callback.call(rv.delete(:response))

    # done
    rv

  end

  def self.translate_to_response(e:)
    args = {}
    args[:status] = 'error'
    args[:action] = 'response'
    if e.is_a?(::SP::Job::JSONAPI::Error)
      args[:status_code]  = e.status_code
      args[:content_type] = e.content_type
      args[:response]     = e.body
    elsif 'jruby' != RUBY_ENGINE && e.is_a?(::SP::Job::BrokerOAuth2Client::InvalidToken)
      args[:status_code]  = 401
      args[:content_type] = ''
      args[:response]     = ''
    else
      ap e.backtrace
      e = ::SP::Job::JSONAPI::Error.new(status: 500, code: '999', detail: e.message)
      args[:status_code]  = e.status_code
      args[:content_type] = e.content_type
      args[:response]     = e.body
    end
    args
  end

  #
  # Report exception to rollbar
  #
  # @param j Job ID
  # @param a Job Body
  # @param e Exception
  #
  def self.rollbar(job_id:, job_body:, exception:)
    $roolbar_mutex.synchronize {
      if $rollbar
        if exception.instance_of? ::SP::Job::JobException
          exception.job[:password] = '<redacted>'
          Rollbar.error(exception, exception.message, { job: exception.job, args: exception.args})
        elsif exception.is_a?(::SP::Job::JSONAPI::Error)
          [:access_token, :refresh_token, :password].each do | s |
            if job_body.has_key?(s)
              job_body[s] = '<redacted>'
            end
          end
          Rollbar.error(exception, exception.message, { job: job_id, args: job_body, response: exception.body })
        else
          Rollbar.error(exception)
        end
      end
    }
  end

end
