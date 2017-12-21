#
# Copyright (c) 2011-2017 Cloudware S.A. All rights reserved.
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
    module UploadedImageConverter
      extend SP::Job::Common

      def self.perform (job)

        throw Exception.new("i18n_entity_id_must_be_defined") if job[:entity_id].nil? || job[:entity_id].to_i == 0

        step        = 100 / (job[:copies].size + 1)
        progress    = step
        original    = File.join($config[:paths][:temporary_uploads], job[:original])
        destination = File.join($config[:paths][:uploads_storage], job[:entity], id_to_path(job[:entity_id]), job[:folder])

        #
        # Check the original image, check format and limits
        # 
        FileUtils::mkdir_p destination
        update_progress(progress: progress, message: 'i18n_reading_original_$image', image: job[:original])
        img_info = %x[identify #{original}]
        m = %r[.*\.ul\s(\w+)\s(\d+)x(\d+)\s.*].match img_info
        if $?.success? == false
          raise_error(message: 'i18n_invalid_image')
        end
        if m.size != 4 
          raise_error(message: 'i18n_invalid_image', rollbar: false)
        end
        unless $config[:options][:formats].include? m[1]
          raise_error(message: 'i18n_unsupported_$format', format: m[1], rollbar: false)
        end
        if m[2].to_i > $config[:options][:max_width]
          raise_error(message: 'i18n_image_too_wide_$width$max_width', width: m[2], max_width:  $config[:options][:max_width], rollbar: false)
        end
        if m[3].to_i > $config[:options][:max_height]
          raise_error(message: 'i18n_image_too_tall_$height$max_height', height: m[3], max_height: $config[:options][:max_height], rollbar: false)
        end

        barrier = true # To force progress on first scalling

        #
        # Iterate the copies array
        #
        job[:copies].each do |copy|
          %x[convert #{original} -geometry #{copy[:geometry]} #{File.join(destination, copy[:name])}]
          unless $?.success?
            logger.error("convert failed to scale #{original} to #{copy[:geometry]}")
            raise_error(message: 'i18n_internal_error')
          end
          progress += step
          update_progress(progress: progress, message: 'i18n_scalling_image_$name$geometry', name: copy[:name], geometry: copy[:geometry], barrier: barrier)
          logger.debug("Scaled to geometry #{copy[:geometry]}")
          barrier = false
        end

        # Closing arguments, all done
        update_progress(status: 'completed', message: 'i18n_image_conversion_complete', link: File.join('/',job[:entity], id_to_path(job[:entity_id]), job[:folder], 'logo_template.png'))

        # Remove original file
        FileUtils::rm_f(original) if $config[:options][:delete_originals] 

      end

    end # UploadedImageConverter
  end # Job
end # SP
