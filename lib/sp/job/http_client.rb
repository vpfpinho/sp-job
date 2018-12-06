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
# A helper class to do HTTP request without session management.
#

require_relative 'curl_http_client'      unless RUBY_ENGINE == 'jruby'
require_relative 'manticore_http_client' if RUBY_ENGINE == 'jruby'

module SP
  module Job
    class HttpClient < EasyHttpClient

      def self.get_klass
        RUBY_ENGINE == 'jruby' ? ManticoreHTTPClient : CurlHTTPClient
      end

      def self.post(url:, headers:, body:, expect:)
        get_klass.post(url: url, headers: headers, body: body, expect: expect)
      end

      def self.get(url:)
        get_klass.get(url: url)
      end

    end
  end
end