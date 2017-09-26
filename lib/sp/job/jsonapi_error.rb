#!/usr/bin/env ruby
#
# encoding: utf-8
#
# Copyright (c) 2017 Cloudware S.A. Allrights reserved
#
# Helper to obtain tokens to access toconline API's.
#

module SP
  module Job

    #
    #  Helper class to transform an error into json api format.
    #
    class JSONAPIError < StandardError

      # {
      #   "errors": [
      #     {
      #       "status": nullptr,
      #       "code": nullptr,
      #       "detail": nullptr,
      #       "meta": {
      #         "internal-error": nullptr
      #       }
      #     }
      #   ]
      # }

      private

        @error

      public

      def initialize (code: 500, detail: nil, internal: nil)
        @errors = [
          {
            :code   => code,
            :detail => detail
          }
        ]
        # 4xx
        case code
        when 400
          @errors[0][:status] = "Bad Request"
        when 401
          @errors[0][:status] = "Unauthorized"
        when 403
          @errors[0][:status] = "Forbidden"
        when 404
          @errors[0][:status] = "Not Found"
        when 405
          @errors[0][:status] = "Method Not Allowed"
        when 406
          @errors[0][:status] = "Not Acceptable"
        when 408
          @errors[0][:status] = "Request Timeout"
        # 5xx
        when 501
          @errors[0][:status] = "Not Implemented"
        else
        # other
          @errors[0][:status] = "Internal Server Error"
        end
        @errors[0][:status] = "#{code} #{@errors[0][:status]}"
        if nil != internal
          @errors[0][:meta] = { :'internal-error' => internal }
        end
      end

      def code ()
        return @errors[0][:code]
      end

      def content_type ()
        "application/vnd.api+json;;charset=utf-8"
      end

      def body ()
        {
          :errors => @errors
        }
      end

      def content_type_and_body ()
        [ content_type(), body() ]
      end

    end

  end # Job module
end # SP module
