#!/usr/bin/env ruby
#
# encoding: utf-8
#
# Copyright (c) 2017 Cloudware S.A. Allrights reserved
#
# Helper to obtain tokens to access toconline API's.
#

require 'sp/job/common'

module SP
  module Job
    module JSONAPI

      class Error < ::SP::Job::Common::Exception
        include ::SP::Job::HttpStatusCode

        def initialize(status:, code:, detail:, internal:nil)
          body = {
             errors: [
               {
                 code: "#{code}",
                 detail: "#{detail}",
                 status: "#{status} - #{self.http_reason(code: status)}"
               }
            ]
          }
          if nil != internal
            body[:meta] = {
              'internal-error' => internal
            }
          end
          super(status_code: status, content_type: 'application/vnd.api+json;charset=utf-8', body: body)
        end

        def code
          @body[:errors][0][:code]
        end

        def message
          @body[:errors][0][:detail]
        end

        def content_type_and_body
          [ 'application/vnd.api+json', message ]
        end

      end # class Error

    end # JSONAPI module
  end # Job module
end # SP module
