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

module SP
  module Job
    class EasyHttpClient

      class Error < StandardError

        attr_accessor :method
        attr_accessor :url

        attr_accessor :code
        attr_accessor :status
        attr_accessor :message
        attr_accessor :detail

        def initialize(method:, url:, code:, message:, detail: nil)
          @method  = method
          @url     = url
          @code    = code
          @status  = EasyHttpClient.http_reason(code: code)
          @message = message
          @detail  = detail
        end

      end

      class InternalError < Error

        attr_accessor :object

        def initialize(method:, url:, code: 500, message: nil, object: nil)
          super(method: method, url: url, code: code, message: message)
          @object = object
        end

      end

      class CouldNotNonnect < Error
        
        def initialize(method:, url:, code: 500, message: nil)
          super(method: method, url: url, code: code, message: message || "Unable to establish connection to #{url}!")
        end

      end

      class SourceFileNotFound < Error

        def initialize(method:, url:, file:, code: 500, message: nil)
          super(method: method, url: url, code: code, message: message || "Source file #{file} not found!")
        end

      end

      @@REASONS = {
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-Status',
        226 => 'IM Used',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        306 => 'Reserved',
        307 => 'Temporary Redirect',
        308 => 'Permanent Redirect',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => "I'm a Teapot",
        422 => 'Unprocessable Entity',
        423 => 'Locked',
        424 => 'Failed Dependency',
        426 => 'Upgrade Required',
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        506 => 'Variant Also Negotiates',
        507 => 'Insufficient Storage',
        510 => 'Not Extended'
      }

      def self.http_reason(code:)
        return @@REASONS[code]
      end

      def self.head(url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.get(url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

      def self.post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplementedError
      end

    protected


      #
      # Test some of response fields agains expected ones
      #
      # @param response
      # @param expect
      #
      def self.raise_if_not_expected(response:, expect:)
        # if 'expect' is no provided
        if nil == expect
          # done
          return response
        end
        # compare status code
        if response[:code] != expect[:code]
          if 401 == response[:code]
            raise ::SP::Job::JSONAPI::Error.new(status: response[:code], code: 'A01', detail: nil)
          else
            raise ::SP::Job::JSONAPI::Error.new(status: response[:code], code: 'B01', detail: nil)
          end
        end
        # compare content-type
        if response[:content][:type] != expect[:content][:type]
          raise ::SP::Job::JSONAPI::Error.new(status: 500, code: 'I01', detail: "Unexpected 'Content-Type': #{response[:content][:type]}, expected #{expect[:content][:type]}!")
        end
        # done
        response
      end # function 'raise_if_not_expected'

    end # class 'EasyHttpClient'

  end # module 'Job'
end # module 'SP'
