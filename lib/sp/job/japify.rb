# coding: utf-8
#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
#
# This file is part of sp-job.
#
# This mix-in adapts a front-end job for use with the JSON api 
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
    module Japify

      #
      # Replace default send response to serialize the response object
      # as inside a json:api object response
      #      
      def send_response (args)
        args[:content_type] = 'application/vnd.api+json;charset=utf-8'
        args[:response] = { 
          data: {
            type: jsonapi_type,
            id: args[:response][:id] || '0',
            attributes: args[:response]
          }
        }
        _send_response(args)
      end

      #
      # Replace default raise error so that errors are serialized json:api style
      #
      def raise_error (args)
        send_error(args[:status_code] || 500, args[:simple_message] || args[:message], args[:code])
        raise ::SP::Job::JobException.new(args: args, job: thread_data.current_job)
      end
    
      #
      # Replace default report error so that errors are serialized json:api style
      #
      def report_error (args)
        send_error(args[:status_code] || 400, args[:simple_message] || args[:message], args[:code])
        raise ::SP::Job::JobAborted.new(args: args, job: thread_data.current_job)
      end

      #
      # Handler for (un)controlled errors
      #
      def on_failure (e, *args)
        if e.is_a?(::SP::Job::EasyHttpClient::Error)
          send_error(e.code.to_i, e.status)
        else
          send_error(500, e.message.strip)
        end
      end

      #
      # Send error JSON api style
      #
      # @param status_code the HTTP status code
      # @param message the message that will be returned with error
      # @param code the report code
      #
      def send_error (status, message, code = nil)
        logger.info "Failed with status #{status}, #{message}".yellow
        _send_response(
          content_type: 'application/vnd.api+json;charset=utf-8',
          status_code: status,
          response: {
            errors: [{
              status: status.to_s,
              code: code || 'JA000',
              detail: message
            }]
          }
        )
      end

    end # module Japify
  end # module Job
end # module SP
