# coding: utf-8
#
# Copyright (c) 2011-2023 Cloudware S.A. All rights reserved.
#
# This file is part of sp-job.
#
# And this is the mix-in we'll apply to Job execution classes
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

if 'jruby' == RUBY_ENGINE
  require 'securerandom'
end

module SP
  module Job

    class SIGUSR2Handler

      attr_reader :linger_tube

      #
      # Initialize instance for a SIGUSR2 Handler.
      #
      # @param ctx ::SP::Job::Common + Backburner
      # @param process Name.
      #
      def initialize(ctx:, process:)
        @ctx             = ctx
        @mutex           = Mutex.new
        @workers         = []
        @signal_received = false
        @shutdown        = false
        @linger_tube     = "A-SIGUSR2-LIMBO-FOR-#{process}"
        # ... SIGUSR2 TAKEOVER ...
        @ctx.logger.info "• Installing Signal Handler v2 for 'SIGUSR2'".cyan
        Signal.trap('SIGUSR2') {
          @ctx.logger.info "• Signal 'SIGUSR2' received...".yellow
          Thread.new {
            @ctx.logger.info "• Scheduling signal 'SIGUSR2' processing...".yellow
            begin
              @mutex.synchronize {
                @signal_received = true
              }
            rescue Exception => e
              # Forward unexpected exceptions to the main thread for proper handling
              @ctx.logger.fatal e.to_s.red
              Thread.main.raise(e)
            end
          }
        }
      end

      #
      # Keep track of a worker and it's thread.
      #
      # @param worker Worker class instance - for mapping / read only purposes only
      # @param thread Thread class instance - for mapping / read only purposes only
      #
      def track(worker:, thread:)
        @mutex.synchronize {
          @workers << { uuid: "#{Process.pid}-#{1 + @workers.count}-#{SecureRandom.uuid}", worker: worker, thread: thread}
        }
      end

      #
      # Forget previously tracked a worker and it's thread.
      #
      # @param worker Worker class instance - for mapping / read only purposes only
      # @param thread Thread class instance - for mapping / read only purposes only
      #
      def untrack(worker:, thread:)
        __index = -1
        @mutex.synchronize {
          @workers.each_with_index do | w, index |
            if w[:thread] == thread
              __index = index
            end
          end
          @workers.delete_at(__index) if __index > -1
        }
        return __index > -1
      end

      #
      # @return True SIGUSR2 was received
      #
      def signal_received?()
        rv = false
        @mutex.synchronize {
          rv = @signal_received
        }
        return rv
      end

      #
      # @return Number of workers running.
      #
      def number_of_tracked_workers()
        rv = 0
        @mutex.synchronize {
          rv = @workers.count
        }
        return rv
      end

      #
      # @return True if it's time to shutdown.
      #
      def shutdown()
        # shutdown already scheduled?
        rv = false
        @mutex.synchronize {
          rv = @shutdown
        }
        # ... yes ...
        if true == rv
          # ... nothing to do here ...
          return rv
        end
        # ... no, but can he scheduled now?
        rv = -1
        @mutex.synchronize {
          rv = @workers.count
          @shutdown = ( 0 == rv )
        }
        # ... no ...
        if 0 != rv
          # ... nothing to do here ...
          return false
        end
        # yes, schedule shutdown now ...
        Thread.new do
          # give some for threads exit
          for value in (5).downto(1)
            @ctx.logger.info  "• Exit in #{value} second(s)..."
            sleep 1
          end
          # close connection
          $beaneater.close
          # and exit process
          exit 0
        end
      end

      public

      #
      # One-shot initializer.
      #
      # @param ctx ::SP::Job::Common + Backburner
      # @param process Name.
      #
      def self.install(ctx:, process: $args[:program_name])
        if nil != $wsh
          raise "SIGUSR2Handler already initialized!"
        end
        $wsh = ::SP::Job::SIGUSR2Handler.new(ctx: ctx, process: $args[:program_name])
      end

      #
      # @return True if shared instance was initialized.
      #
      def self.initialized?()
        return nil != $wsh
      end

      #
      # @return True SIGUSR2 was received
      #
      def self.signal_received?()
        if true == SIGUSR2Handler.initialized?
          return $wsh.signal_received?
        end
      end

      #
      # Keep track of a worker and it's thread - if previously initialized.
      #
      # @param worker Worker class instance - for mapping / read only purposes only
      # @param thread Thread class instance - for mapping / read only purposes only
      #
      def self.track_worker_if_enabled(worker:, thread:)
        if true == SIGUSR2Handler.initialized?
          $wsh.track(worker: worker, thread: thread)
        end
      end

      #
      # Forget previously tracked a worker and it's thread.
      #
      # @param worker Worker class instance - for mapping / read only purposes only
      # @param thread Thread class instance - for mapping / read only purposes only
      #
      def self.untrack_worker_if_enabled(worker:, thread:)
        if true == SIGUSR2Handler.initialized?
          return $wsh.untrack(worker: worker, thread: thread)
        end
        return false
      end

      #
      # @return True if it's time to shutdown.
      #
      def self.shutdown()
        if true == SIGUSR2Handler.initialized?
          return $wsh.shutdown()
        end
        return false
      end

      #
      # @return Number of workers running.
      #
      def self.number_of_tracked_workers()
        if true == SIGUSR2Handler.initialized?
          return $wsh.number_of_tracked_workers()
        end
        return -1
      end

      #
      # @return Linger tube name.
      #
      def self.linger_tube()
        if true == SIGUSR2Handler.initialized?
          return $wsh.linger_tube
        end
        return nil
      end

    end

  end # module 'Job'
end # module 'SP'
