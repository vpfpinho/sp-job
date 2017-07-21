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

# https://github.com/ruby-concurrency/concurrent-ruby
# Follow https://github.com/bbatsov/ruby-style-guide

module Sp
  module Job
    class BeanRunner

      @@prefix        = nil
      @@rollbar       = false
      @@bury          = false
      @@tube          = nil
      @@args          = {}
      @@min_progress  = 3
      @@option_parser = nil
      @@config        = nil

      def self.static_initialization
        unless @@prefix.nil?
          return
        end
        @@prefix  = OS.mac? ? '/usr/local' : '/'
        @@tube    = File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME))
        @@args[:program_name] = File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME))
        @@args[:config_file]  = File.join(@@prefix, 'etc', @@args[:program_name], 'conf.json')

        #
        # Parse command line arguments
        #
        @@option_parser = OptionParser.new do |opts|
          opts.banner = "Usage: #{$PROGRAM_NAME} ARGS"
          opts.on('-c', '--config=CONFIG.JSON', "path to json configuration file (default: '#{@@args[:config_file]}')") { |v| @@args[:config_file] = File.expand_path(v) }
        end
        @@option_parser.parse!

        #
        # Read configuration
        #
        @@config = JSON.parse(File.read(File.expand_path(@@args[:config_file])), symbolize_names: true)
        @@min_progress = @@config[:options] && @@config[:options][:min_progress] ? @@config[:options][:min_progress] : 3
        @@bury         = @@config[:options] && @@config[:options][:bury] == true

        #
        # Configure rollbar
        #
        unless @@config[:rollbar].nil?
          @@rollbar = true
          Rollbar.configure do |config|
            config.access_token = @@config[:rollbar][:token] if @@config[:rollbar][:token]
            config.environment  = @@config[:rollbar][:environment] if @@config[:rollbar] && @@config[:rollbar][:environment]
          end
        end
      end

      def initialize
        BeanRunner.static_initialization
        @progress           = 0
        @check_db_life_span = false
        @beanstalk          = Beaneater.new("#{@@config[:beanstalkd][:host]}:#{@@config[:beanstalkd][:port]}")
        @redis              = Redis.new(:host => @@config[:redis][:host], :port => @@config[:redis][:port], :db => 0)
        @status_dirty       = Concurrent::AtomicBoolean.new
        @status_timer       = Concurrent::TimerTask.new(execution_interval: @@min_progress) do
          if @status_dirty.true?
            @status_dirty.make_false
            update_job_status_on_redis
          else
            @status_timer.shutdown
          end
        end
        database_connect()
        puts "Yupi connected to #{@beanstalk.connection}"
      end

      def id_to_path (id)
        "%03d/%03d/%03d/%03d" % [
          (id % 1000000000000) / 1000000000,
          (id % 1000000000)    / 1000000   ,
          (id % 1000000)       / 1000      ,
          (id % 1000)
        ]
      end

      def run
        @beanstalk.jobs.register(@@tube) do |job|
          begin
            @job_status = {}
            @job_status[:progress] = 0
            job_body               = JSON.parse(job.body, symbolize_names: true)
            @redis_key             = @@tube + '/' + job_body[:id]
            @validity              = job_body[:validity].nil? ? 300 : job_body[:validity].to_i
            if @@config[:options] && @@config[:options][:jsonapi] == true
              raise "Job didn't specify the mandatory field prefix!" if job_body[:prefix].blank?
              @jsonapi.set_url(job_body[:prefix])
            end
            process(job_body)
          rescue Exception => e
            puts [e, e.backtrace] if @@config[:options] && @@config[:options][:debug_exceptions]
            update_progress(status: 'error', message: e)
            if @@rollbar
              Rollbar.error(e)
            end
            if @@bury
              raise e
            end
          end
        end
        @beanstalk.jobs.process!
        @beanstalk.close
      end

      def update_progress (args)

        step     = args[:step]
        status   = args[:status]
        progress = args[:progress]
        barrier  = args[:barrier]

        if args.has_key? :message
          message = [ args[:message] ]
          args.each do |key, value|
            next if [:step, :progress, :message, :status, :barrier].include? key
            message << key
            message << value
          end
        else
          message = nil
        end

        @job_status[:progress] = (@job_status[:progress] + step.to_f).round(2) unless step.nil?
        @job_status[:message]  = message unless message.nil?
        @job_status[:status]   = status.nil? ? 'in-progress' : status

        if status == 'complete' || status == 'error' || barrier
          unless barrier
            @status_timer.shutdown
          end
          @status_dirty.make_false
          update_job_status_on_redis
        elsif @status_timer.running?
          @status_dirty.make_true
        else
          update_job_status_on_redis
          @status_timer.execute
        end
      end

      def update_job_status_on_redis
        @redis.pipelined do
          redis_str = @job_status.to_json
          @redis.publish @redis_key, redis_str
          @redis.set     @redis_key, redis_str
          @redis.expire  @redis_key, @validity
        end
      end

      def get_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        @jsonapi.adapter.get!(path, params, jsonapi_args)
      end
      def post_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        @jsonapi.adapter.post!(path, params, jsonapi_args)
      end
      def patch_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        @jsonapi.adapter.patch!(path, params, jsonapi_args)
      end
      def delete_jsonapi!(path, jsonapi_args)
        check_db_life_span()
        @jsonapi.adapter.delete!(path, jsonapi_args)
      end

      def db_exec(query)
        unless query.nil?
          check_db_life_span()
          @pg.exec(query)
        end
      end

      private

      def database_connect
        @pg.close if !@pg.nil? && !@pg.finished?
        current_url = (@jsonapi.nil? ? nil : @jsonapi.url)
        @jsonapi.close unless @jsonapi.nil?
        @pg = @jsonapi = nil
        unless @@config[:postgres].nil? || @@config[:postgres][:conn_str].nil?
          @pg = PG.connect(@@config[:postgres][:conn_str])
          # Connect to postgresql
          define_db_life_span_treshhold()
          if @@config[:options][:jsonapi] == true
            @jsonapi = SP::Duh::JSONAPI::Service.new(@pg, current_url)
          end
        end
      end

      def define_db_life_span_treshhold
        min = @@config[:postgres][:min_queries_per_conn]
        max = @@config[:postgres][:max_queries_per_conn]
        if (!max.nil? && max > 0) || (!min.nil? && min > 0)
          @db_life_span       = 0
          @check_db_life_span = true
          new_min, new_max = [min, max].minmax
          new_min = new_min if new_min <= 0
          if new_min + new_min > 0
            @db_treshold = (new_min + (new_min - new_min) * rand).to_i
          else
            @db_treshold = new_min.to_i
          end
        end
      end

      def check_db_life_span
        return unless @check_db_life_span
        @db_life_span += 1
        if @db_life_span > @db_treshold
          # Reset pg connection
          database_connect()
        end
      end

    end
  end
end

