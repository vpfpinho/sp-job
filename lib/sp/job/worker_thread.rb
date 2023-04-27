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

require 'java'
require 'sp/job/sigusr2_handler'

module SP
  module Job

    class WorkerThread < ::SP::Job::Worker

      @@thread_counter = 0

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
            $thread_data[Thread.current]       = ::SP::Job::ThreadData.new
            $thread_data[Thread.current].index = @@thread_counter
            @@thread_counter += 1
            logger.info "Thread for #{tube_names.join(',')} #{Thread.current}"
            loop do
              by_reserve_timeout = false
              begin
                by_reserve_timeout = work_one_job(connection)
                # this is optional, it only works if reserve_timeout was previously set
                if true == by_reserve_timeout
                  # check if should shutdown
                  if true == ::SP::Job::SIGUSR2Handler.signal_received?()
                    # ... and for that, untrack this thread ...
                    if true == ::SP::Job::SIGUSR2Handler.untrack_worker_if_enabled(worker: self, thread: Thread.current)
                      # log
                      logger.info "- #{Thread.current} ignoring %s".yellow % [ "#{tube_names}".white ]
                      # ... according to beanstalk protocol, at least one tube must be watched ...
                      connection.beanstalk.tubes.watch(::SP::Job::SIGUSR2Handler.linger_tube)
                      # ... now ignore all other tubes ...
                      connection.beanstalk.tubes.ignore(*tube_names)
                    else
                      if true == ::SP::Job::SIGUSR2Handler.shutdown()
                        break
                      end
                    end
                  end
                  # try to reserve next job
                  next
                end
              rescue Beaneater::NotFoundError => bnfe
                # Do nothing if try to delete the task and it´s not found
              rescue Beaneater::DeadlineSoonError => dse
                # By default there is nothing we can do to speed up
              rescue Backburner::Job::JobTimeout => jte
                # What to do?
                logger.info "Thread #{Thread.current} job timeout".yellow
                Rollbar.warning(jte)
              rescue java.lang.Throwable => je
                logger.error "Thread #{Thread.current} caught exception ".red
                je.backtrace.each_with_index do | l, i |
                  logger.error "%3s %1s%s%s %s" % [ ' ', '['.white, i.to_s.rjust(3, ' ').white, ']'.white , l.yellow ]
                end
                Rollbar.error(je)
              rescue => e
                Rollbar.error(e)
              end
              logger.info "JOB FINISHED -> Thread for #{tube_names.join(',')} #{Thread.current}" if false == by_reserve_timeout
              unless connection.connected?
                log_error "Connection to beanstalk closed, exiting now"
                Kernel.exit
              end
            end
            logger.info "Thread #{Thread.current} exiting".yellow
            $threads.delete(Thread.current)
            $thread_data.delete Thread.current
          }
          # present worker to signal handler
          ::SP::Job::SIGUSR2Handler.track_worker_if_enabled(worker: self, thread: $threads.last)  
        end
      end

    end # Worker
  end # Module Job
end # Module SP
