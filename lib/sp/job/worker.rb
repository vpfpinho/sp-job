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
module SP
  module Job

    class Worker < Backburner::Workers::Simple

      def start
        prepare
        loop do 
            begin
              work_one_job(connection)
            rescue Beaneater::NotFoundError => bnfe
              # Do nothing if try to delete the task and it´s not found
            rescue Beaneater::DeadlineSoonError => dse 
              # By default there is nothing we can do to speed up
            rescue Backburner::Job::JobTimeout => jte
              # What to do?
            end
          unless connection.connected?
            log_error "Connection to beanstalk closed, exiting now"
            Kernel.exit
          end
        end
      end

    end # Worker
  end # Module Job
end # Module SP