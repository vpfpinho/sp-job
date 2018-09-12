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

#require 'byebug'
require 'awesome_print'
require 'rollbar'
require 'redis'
require 'backburner'
require 'json'
require 'fileutils'
require 'optparse'
require 'os'
require 'pg'
require 'oauth2'         unless RUBY_ENGINE == 'jruby'
require 'oauth2-client'  unless RUBY_ENGINE == 'jruby'
require 'curb'           unless RUBY_ENGINE == 'jruby'
require 'erb'
require 'ostruct'
require 'json'
require 'mail'
require 'uri'

require 'sp/job'
require 'sp/job/version'
require 'sp/job/worker'
require 'sp/job/worker_thread'
require 'sp/job/common'
require 'sp/job/unique_file'
require 'sp/job/jwt'
require 'sp/job/http_client'
require 'sp/job/query_params'
require 'sp/job/broker_http_client'    unless RUBY_ENGINE == 'jruby'
require 'sp/job/broker_oauth2_client'  unless RUBY_ENGINE == 'jruby'

# JSONAPI library classes
require 'sp/jsonapi'
require 'sp/jsonapi/exceptions'
require 'sp/jsonapi/resource_publisher'
# Parameters class
require 'sp/jsonapi/parameters'
# Service classes
require 'sp/jsonapi/service'
require 'sp/jsonapi/configuration'
# Adpater classes
require 'sp/jsonapi/adapters/base'
require 'sp/jsonapi/adapters/raw_db'
require 'sp/jsonapi/adapters/db'
require 'sp/jsonapi/model/base'
# API documentationlibrary classes
require 'sp/jsonapi/doc/generator'