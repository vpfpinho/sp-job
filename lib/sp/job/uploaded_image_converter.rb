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
# require 'sp-job'
# require 'sp/job/back_burner'
# require 'sp/job/uploaded_image_converter'
#
# class CLASSNAME < ::SP::Job::UploadedImageConverter
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
    class UploadedImageConverter
      extend SP::Job::Common

      #
      # One shot code that configures the converter into class variables
      #
      @@upload = URI.parse(config[:urls][:upload_internal])
      if @@upload.host == 'localhost' || @@upload.host == '127.0.0.1' || @@upload.host == config[:machine][:internal_ip]
        @@ssh = ''
        @@src = config[:paths][:temporary_uploads]
        @@dst = config[:paths][:uploads_storage]
      else
        @@ssh = "ssh #{@@upload.host} "
        @@src = config[:paths][:remote_temporary_uploads]
        @@dst  = config[:paths][:remote_uploads_storage]
      end

      @@tube_options = default_tube_options()
      if (config[:jobs][$args[:program_name].to_sym][:'uploaded-image-converter'])
        @@tube_options.merge!(config[:jobs][$args[:program_name].to_sym][:'uploaded-image-converter'])
      end
      @@tube_options[:transient] = true

      def self.tube_options
        return @@tube_options
      end

      #
      # JOB execution method main entry point
      #
      def self.perform (job)

        raise_error(message: 'i18n_entity_id_must_be_defined') if job[:to_entity_id].nil? || job[:to_entity_id].to_i == 0

        step        = 100 / (job[:copies].size + 1)
        progress    = step
        original    = File.join(@@src, job[:original])
        destination = File.join(@@dst, job[:entity], id_to_path(job[:to_entity_id]), job[:folder])

        if @@ssh == ''
          FileUtils::mkdir_p destination
        else
          %x[#{@@ssh}mkdir -p #{destination}]
          unless $?.success?
            raise_error(message: 'i18n_internal_error', info: "unable to create remote directory")
          end
        end

        #
        # Check the original image, check format and limits
        #
        update_progress(progress: progress, message: 'i18n_reading_original_$image', image: job[:original_file_path] || job[:original])
        img_info = %x[#{@@ssh}identify #{original}]
        m = %r[.*\.ul\s(\w+)\s(\d+)x(\d+)\s.*].match img_info
        if $?.success? == false
          return report_error(message: 'i18n_invalid_image', info: "Image #{original} can't be identified '#{img_info}'")
        end
        if m.nil? || m.size != 4
          return report_error(message: 'i18n_invalid_image', info: "Image #{original} can't be identified '#{img_info}'")
        end
        unless @@tube_options[:formats].include? m[1]
          return report_error(message: 'i18n_unsupported_$format', format: m[1])
        end
        if m[2].to_i > @@tube_options[:'max-width']
          return report_error(message: 'i18n_image_too_wide_$width$max_width', width: m[2], max_width:  @@tube_options[:'max-width'])
        end
        if m[3].to_i > @@tube_options[:'max-height']
          return report_error(message: 'i18n_image_too_tall_$height$max_height', height: m[3], max_height: @@tube_options[:'max-height'])
        end

        barrier = true # To force progress on first scalling

        #
        # Iterate the copies array
        #
        job[:copies].each do |copy|
          %x[#{@@ssh}convert #{original} -geometry #{copy[:geometry]} #{File.join(destination, copy[:name])}]
          unless $?.success?
            raise_error(message: 'i18n_internal_error', info: "convert failed to scale #{original} to #{copy[:geometry]}")
          end
          progress += step
          update_progress(progress: progress, message: 'i18n_scalling_image_$name$geometry', name: copy[:name], geometry: copy[:geometry], barrier: barrier)
          logger.debug("Scaled to geometry #{copy[:geometry]}")
          barrier = false
        end

        #
        # Closing arguments, all done
        #
        return { hostname: config[:urls][:upload_public], path: File.join('/',job[:entity], id_to_path(job[:to_entity_id]), job[:folder])}

      end

    end # UploadedImageConverter
  end # Job
end # SP
