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

require 'cgi'

module SP
  module Job
    module QueryParams

      def self.encode(value, key = nil)
        case value
        when Hash  then value.map { |k,v| encode(v, append_key(key,k)) }.join('&')
        when Array then value.map { |v| encode(v, "#{key}[]") }.join('&')
        when nil   then ''
        else
          "#{key}=#{CGI.escape(value.to_s)}"
        end
      end

      private

      def self.append_key(root_key, key)
        root_key.nil? ? key : "#{root_key}[#{key.to_s}]"
      end
    end
  end
end
