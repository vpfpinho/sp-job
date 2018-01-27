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

      def initialize (tube_names=nil)
        super(tube_names)
      end

      def start
        prepare
        loop do 
          work_one_job
          unless connection.connected?
            log_error "Connection to beanstalk closed, exiting now"
            exit
          end
        end
      end

      #
      # This method was highjacked from the base class to insert the job cancel handling
      #

      # Performs a job by reserving a job from beanstalk and processing it
      #
      # @example
      #   @worker.work_one_job
      # @raise [Beaneater::NotConnected] If beanstalk fails to connect multiple times.
      def work_one_job(conn = connection)
        begin
          job = reserve_job(conn)
        rescue Beaneater::TimedOutError => e
          return
        end
  
        self.log_job_begin(job.name, job.args)
        job.process
        self.log_job_end(job.name)
  
      # SP patch to handle the cancel event
      #
      # This exception:
      #  1. is not sent to the rollbar
      #  2. does not bury the job, instead the job is deleted
      #  3. 
      #
      rescue ::SP::Job::JobCancelled
        extend SP::Job::Common  # to lazily mix-in report_error 

        $redis.hset($job_key, 'cancelled', true) 
        job.delete
        return report_error(message: 'i18n_job_cancelled')
      rescue Backburner::Job::JobFormatInvalid => e
        self.log_error self.exception_message(e)
      rescue => e # Error occurred processing job
        self.log_error self.exception_message(e)
  
        unless job
          self.log_error "Error occurred before we were able to assign a job. Giving up without retrying!"
          return
        end
  
        # NB: There's a slight chance here that the connection to beanstalkd has
        # gone down between the time we reserved / processed the job and here.
        num_retries = job.stats.releases
        retry_status = "failed: attempt #{num_retries+1} of #{queue_config.max_job_retries+1}"
        if num_retries < queue_config.max_job_retries # retry again
          delay = queue_config.retry_delay_proc.call(queue_config.retry_delay, num_retries) rescue queue_config.retry_delay
          job.retry(num_retries + 1, delay)
          self.log_job_end(job.name, "#{retry_status}, retrying in #{delay}s") if job_started_at
        else # retries failed, bury
          job.bury
          self.log_job_end(job.name, "#{retry_status}, burying") if job_started_at
        end
  
        handle_error(e, job.name, job.args, job)
      end

      private

    end # Worker
  end # Module Job
end # Module SP