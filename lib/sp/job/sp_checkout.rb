#
# Copyright (c) 2011-2017 Servicepartner LDA. All rights reserved.
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
### IMPORTANT - serious this is important
# YOU must require 'rmagick' on the script that uses this class, should be used like this
#
# How to use this to implement a customized image conversion
#
# require 'rmagick'
# require 'sp-job'
# require 'sp/job/back_burner'
# require 'sp/job/uploaded_image_converter'
#
# class CLASSNAME
#   extend SP::Job::Common
#   extend SP::Job::UploadedImageConverter
#
#   def self.perform(job)
#
#     ... Your code before the image conversion ...
#
#     SP::Job::UploadedImageConverter.perform(job)
#
#     ... your code after the conversion ...
#
#   end
# end
#
# Backburner.work
#

module SP
  module Job
    module SpCheckout
      extend SP::Job::Common

      def self.perform (job)

      end

    end
  end # Job
end # SP
