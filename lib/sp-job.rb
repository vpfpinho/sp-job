#
# Copyright (c) 2011-2016 Servicepartner LDA. All rights reserved.
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

# require 'byebug'
require 'awesome_print'
require 'rollbar'
require 'redis'
require 'backburner'
require 'json'
require 'fileutils'
require 'concurrent'
require 'optparse'
require 'os'
require 'pg'
require 'sp-duh'
require 'oauth2'
require 'oauth2-client'
require 'curb'
require 'rails'
require 'erb'
require 'ostruct'
require 'json'

require 'sp/job'
require 'sp/job/engine'
require 'sp/job/version'
require 'sp/job/bean_runner'
require 'sp/job/worker'
require 'sp/job/back_burner'
require 'sp/job/uploaded_image_converter'
require 'sp/job/broker_oauth2_client'
