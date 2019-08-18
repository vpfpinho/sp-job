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
# How to use this to include generic reports in a job process
#
# require 'document_generator' <<< add this to job
# require 'sp-job'
# require 'sp/job/back_burner'
# require 'sp/job/generic_report' <<< add this to job
#
# GenericReport = ::SP::Job::GenericReport <<< use alias or extend class if needed
#
# Backburner.work('generic-report', ... other tubes )
#

module SP
  module Job
    class GenericReport
      extend SP::Job::Common

      # Hacked version TODO proper JSONAPI resource with included lines and scalars
      def self.get_resource (resource)
        rs = db.exec <<-SQL
          SELECT response FROM jsonapi('GET', 'http://localhost/#{resource}', '', '', '', '', '', '', '');
        SQL
        value = {
          :data => {
                    :type => 'c4_report',
                    :id => 0,
                    :attributes => { :company_name => 'FOO', :company_tax_registration_number => 'BAR' }
          },
          :included => JSON.parse(rs.first['response'], { symbolize_names: true })[:data]
        }
        instance_variable_set("@#{resource}", value)
        return value
      end

      def self.perform (job)

        cdn_uri          = URI(config[:urls][:cdn])
        template_dir     = File.join(File.dirname(File.expand_path($PROGRAM_NAME)), 'templates')
        attachments      = []
        job[:resource] ||= job[:template]

        if job[:resource].kind_of?(Array)
          resources = job[:resource]
        else
          resources = [ job[:resource] ]
        end

        resources.each do |resource|
          excel = DocumentGenerator::HashToExcel.new({
              data: self.get_resource(resource),
              template_file: File.join(template_dir, "#{resource}.xlsx")
          })
          excel.run
          attachments << {
            protocol: cdn_uri.scheme,
            host: cdn_uri.hostname,
            port: cdn_uri.port,
            path: 'attachment',
            file: excel.output_file.sub('/tmp/', '') # TODO Proper tmp striping
          }
        end

        send_email(
            template:    File.join(template_dir, job[:template]),
            to:          job[:to],
            subject:     "#{job[:subject]} #{Date.today.to_s}",
            attachments: attachments
        )
        send_response(message: 'Report completed')

      end

    end # GenericReport
  end # Job
end # SP
