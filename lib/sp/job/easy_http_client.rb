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

      class MissingRequiredHeadersError < StandardError
      end

      class Error < StandardError

        attr_accessor :method
        attr_accessor :url

        attr_accessor :code
        attr_accessor :status
        attr_accessor :message
        attr_accessor :detail

        attr_accessor :object
        attr_accessor :response

        def initialize(method:, url:, code:, message:, detail: nil, object: nil, response: nil)
          @method   = method
          @url      = url
          @code     = code
          @status   = EasyHttpClient.http_reason(code: code)
          @message  = message
          @detail   = detail
          @object   = object
          @response = response
          if nil != object
            if nil == message
              @message = object.class.name()
            end
            if nil == detail
              @detail = object.message
            end
          end
        end # initialize

      end # class 'Error'

      class InternalError < Error

        def initialize(method:, url:, message: nil, detail: nil, object: nil, response: nil)
          super(method: method, url: url, code: 500, message: message, detail: detail, response: response)
        end

      end # class 'InternalError'

      class NotImplemented < Error
        
        def initialize(method:, url:, message: nil, detail: nil, response: nil)
          super(method: method, url: url, code: 501, message: message, detail: detail, response: response)
        end

      end # class 'NotImplemented'

      class CouldNotNonnect < Error

        def initialize(method:, url:, code: 500, message: nil)
          super(method: method, url: url, code: code, message: message || "Unable to establish connection to #{url}!")
        end

      end # class 'CouldNotNonnect'

      class SourceFileNotFound < Error

        def initialize(method:, url:, local_file_uri:, code: 404, message: nil)
          super(method: method, url: url, code: code, message: message || "Source file #{local_file_uri} not found!")
        end

      end # class 'SourceFileNotFound'

      class Unauthorized < Error

        def initialize(method:, url:, message: nil, response: nil)
          super(method: method, url: url, code: 401, message: message, response: response)
        end

      end # class 'Unauthorized'

      class Forbidden < Error

        def initialize(method:, url:, message: nil, response: nil)
          super(method: method, url: url, code: 403, message: message, response: response)
        end

      end # class 'Forbidden'

      class BadRequest < Error

        def initialize(method:, url:, message: nil, response: nil)
          super(method: method, url: url, code: 400, message: message, response: response)
        end

      end # class 'BadRequest'      

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
        raise NotImplemented.new(method: 'HEAD', url: url)
      end

      def self.get(url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'GET', url: url)
      end

      def self.post(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'POST', url: url)
      end

      def self.put(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'PUT', url: url)
      end

      def self.patch(url:, headers: nil, body: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'PATCH', url: url)
      end

      def self.delete(url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'DELETE', url: url)
      end

      def self.upload(origin:, url:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'UPLOAD', url: url)
      end

      def self.get_to_file(url:, headers: nil, to:, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'GET', url: url)
      end

      def self.post_to_file(url:, headers: nil, body:, to:, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'POST', url: url)
      end

      def self.post_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'POST', url: to)
      end

      def self.put_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'PUT', url: to)
      end

      def self.patch_file(uri:, to:, headers: nil, expect: nil, conn_options: nil)
        raise NotImplemented.new(method: 'PATCH', url: to)
      end

    protected


      #
      # Test some of response fields agains expected ones
      #
      # @param method   [REQUIRED] One of GET, POST, PUT, PATCH, DELETE.
      # @param url      [REQUIRED] Request URL.
      # @param response [REQUIRED] Normalized response object, see normalize_response method on HTTP Client ( curl or java ) implementation.
      # @param expect   [OPTIONAL] Expected normalized response first level check, ex: { code: 200, content: { type: 'application/text' } }
      #
      def self.raise_if_not_expected(method:, url:, response:, expect:)
        # if 'expect' is no provided
        if nil == expect
          # nothing to do
          return response
        end
        # compare status code
        if response[:code] != expect[:code]
          case response[:code]
          when 400
            raise EasyHttpClient::BadRequest.new(method: method, url: url, response: response)
          when 401
            raise EasyHttpClient::Unauthorized.new(method: method, url: url, response: response)
          when 403
            raise EasyHttpClient::Forbidden.new(method: method, url: url, response: response)
          else
            raise EasyHttpClient::Error.new(method: method, url: url, code: response[:code], message: nil,
                  detail: nil, object: nil,
                  response: response
            )
          end
        end
        # compare content-type
        if nil != expect[:content]
          if response[:content][:type] != expect[:content][:type]
            raise EasyHttpClient::Error.new(method: method, url: url, code: 500,
                    detail: "Unexpected 'Content-Type': #{response[:content][:type]}, expected #{expect[:content][:type]}!", 
                    response: response
            )
          end
        end
        # done
        return response
      end # function 'raise_if_not_expected'

    end # class 'EasyHttpClient'

  end # module 'Job'
end # module 'SP'
