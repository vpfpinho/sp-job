#
# Copyright (c) 2011-2023 Cloudware S.A. All rights reserved.
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

$workers_mutex = Mutex.new
$workers_mutex.synchronize {
  $workers = []
}

class ReloadHandler
  extend SP::Job::Common

  def self.tube_options
    { transient: true }
  end

  def self.thread_job
    thread_data.job_data
  end

  def self.perform (job)
    $workers_mutex.synchronize {
      $workers.each do | worker |
        if worker.object_id == job[:worker]
          job[:ignore].each do | tube |
            logger.info  "  Worker ##{worker.object_id} will ignore tube #{tube}"
            worker.connection.beanstalk.tubes.ignore(tube)
          end
        end
      end
    }
    $gracefull_exit = true
    check_gracefull_exit(dolog: false)
  end

end # of class 'ReloadHandler'

eval <<DYNAMIC
  class #{$args[:program_name].split('-').collect(&:capitalize).join}Reload < ReloadHandler
    # ...or substitute other stuff in here.
  end
DYNAMIC

module Backburner
  class << self
    def work2(*tubes)
      tubes << "#{$args[:program_name]}-reload"
      require 'byebug' ; debugger
      install_reload_signal_handler
      ::Backburner.work(tubes)
    end
 end
end
  
ap "MAIN : #{Thread.current} ~> #{$args[:program_name]}-reload"

def install_reload_signal_handler
  Signal.trap('SIGUSR2') {
    ap "NEW SIGNAL HANDLER @ #{Thread.current}"
    Thread.new {
      ap "SIGNAL THREAD : #{Thread.current}"
      begin
        $workers_mutex.synchronize {
          $workers.each_with_index do | worker, index |
            ignore = []
            worker.tube_names.each do | tube |
              ignore << tube
            end
            ignore = ignore - ["#{$args[:program_name]}-reload"]
            submit_job(job: { worker: worker.object_id, ignore: ignore }, tube: "#{$args[:program_name]}-reload")
          end
        }          
      rescue Exception => e
        # Forward unexpected exceptions to the main thread for proper handling
        logger.fatal e.to_s.red
        Thread.main.raise(e)
      end
    }
  }
end

# reloader_tube_name = "#{$args[:program_name]}-reload"
# reloader_worker_class = RUBY_ENGINE == 'jruby' ? SP::Job::WorkerThread : SP::Job::Worker

# reloader_worker_class.start(reloader_tube_name)