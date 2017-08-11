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
# encoding: utf-8
#

### IMPORTANT - serious this is important
# YOU must require 'rmagick' on the script that uses this class

module SP
  module Job

    #
    # Beanstalk job that scales uploaded images
    #
    class UploadedImageConverter < BeanRunner

      def process (job)

        raise Exception.new("i18n_entity_id_must_be_defined") if job[:entity_id].nil? || job[:entity_id].to_i == 0

        step        = 100 / (job[:copies].size + 1)
        original    = File.join(@@config[:paths][:temporary_uploads], job[:original])
        destination = File.join(@@config[:paths][:uploads_storage], job[:entity], id_to_path(job[:entity_id]), job[:folder])

        FileUtils::mkdir_p destination
        image = Magick::Image.read(original).first
        update_progress(step: step, message: 'i18n_reading_original_$image', image: job[:original])
        job[:copies].each do |copy|
          img_copy = image.copy()
          img_copy.change_geometry(copy[:geometry].to_s) do |cols, rows, img|
            img.resize!(cols, rows)
          end
          img_copy.write(File.join(destination, copy[:name]))
          update_progress(step: step, message: 'i18n_scalling_image_$name$geometry', name: copy[:name], geometry: copy[:geometry])
          sleep 3
        end
        update_progress(status: 'completed', message: 'i18n_image_conversion_complete', link: File.join('/',job[:entity], id_to_path(job[:entity_id]), job[:folder], 'logo_template.png'))
      end

    end # class

  end
end
