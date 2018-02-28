#
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

    class WorkerThread < Backburner::Workers::Simple

      # Used to prepare job queues before processing jobs.
      # Setup beanstalk tube_names and watch all specified tubes for jobs.
      #
      # @raise [Beaneater::NotConnected] If beanstalk fails to connect.
      # @example
      #   @worker.prepare
      #
      def prepare
        log_info "Working #{tube_names.size} queues: [ #{tube_names.join(', ')} ]"
        $config[:options][:threads].times do 
          connection = new_connection.tap{ |conn| conn.tubes.watch!(*tube_names) }
          connection.on_reconnect = lambda { |conn| conn.tubes.watch!(*tube_names) }

          $threads << Thread.new {
            $thread_data[Thread.current] = ::SP::Job::ThreadData.new
            logger.debug "Thread for #{tube_names.join(',')} #{Thread.current}"
            loop do 
              work_one_job(connection)
              unless connection.connected?
                log_error "Connection to beanstalk closed, exiting now"
                Kernel.exit
              end
            end          
          }
        end
        #end
      end

    end # Worker
  end # Module Job
end # Module SP