#
# Copyright (c) 2011-2017 Servicepartner LDA. All rights reserved.
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

#
# Initialize global data needed for configuration
#
$prefix              = OS.mac? ? '/usr/local' : '/'
$rollbar             = false
$bury                = false
$min_progress        = 3 # TODO to config??
$args                = {
  stdout:       false,
  program_name: File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME)),
  config_file:  File.join($prefix, 'etc', File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME)), 'conf.json'),
  log_file:     File.join($prefix, 'var', 'log', "#{File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME))}.log")
}

#
# Parse command line arguments
#
$option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} ARGS"
  opts.on('-c', '--config=CONFIG.JSON', "path to json configuration file (default: '#{$args[:config_file]}')") { |v| $args[:config_file] = File.expand_path(v) }
  opts.on('-l', '--log=LOGFILE'       , "path to log file (default: '#{$args[:log_file]}')")                   { |v| $args[:log_file]    = File.expand_path(v) }
  opts.on('-d', '--debug'             , "developer mode: log to stdout and print job")                         { $args[:debug]           = true                }
end
$option_parser.parse!

#
# Read configuration
#
$config = JSON.parse(File.read(File.expand_path($args[:config_file])), symbolize_names: true)

#
# Configure rollbar
#
unless $config[:rollbar].nil?
  $rollbar = true
  Rollbar.configure do |config|
    config.access_token = $config[:rollbar][:token] if $config[:rollbar][:token]
    config.environment  = $config[:rollbar][:environment] if $config[:rollbar] && $config[:rollbar][:environment]
  end
end

#
# Configure backburner queue
#
Backburner.configure do |config|

  config.beanstalk_url       = "beanstalk://#{$config[:beanstalkd][:host]}:#{$config[:beanstalkd][:port]}"
  config.tube_namespace      = 'toc-dev' # TODO service id
  config.namespace_separator = '.'
  config.on_error            = lambda { |e| 
    update_progress(status: 'error', message: e)
    if $rollbar
      Rollbar.error(e)
    end
  }
  #config.priority_labels     = { :custom => 50, :useless => 1000 }
  #config.max_job_retries     = 0 # default 0 retries
  #config.retry_delay         = 5 # default 5 seconds
  #config.default_priority    = 65536
  config.retry_delay_proc       = lambda { |min_retry_delay, num_retries| min_retry_delay + (num_retries ** 3) }
  config.respond_timeout        = 120
  config.default_worker         = SP::Job::Worker
  config.logger                 = Logger.new(STDOUT) # $args[:debug] ? Logger.new(STDOUT) : Logger.new($args[:log_file])
  config.logger.formatter = proc do |severity, datetime, progname, msg|
    date_format = datetime.strftime("%Y-%m-%d %H:%M:%S")
    "[#{date_format}] #{severity}: #{msg}\n"
  end
  #config.logger.level = Logger::INFO
  config.logger.datetime_format = "%Y-%m-%d %H:%M:%S" 
  config.primary_queue          = $args[:program_name]
  config.reserve_timeout        = nil
  config.job_parser_proc        = lambda { |body|
    rv = Hash.new
    rv[:class] = $args[:program_name]
    rv[:args] = [JSON.parse(body, :symbolize_names => true)]
    rv 
  }
end

#
# And this is the mix-en we'll apply to Job execution class
# 
module SP
  module Job
    module Common

      def logger
        Backburner.configuration.logger
      end

      def id_to_path (id)
        "%03d/%03d/%03d/%03d" % [
          (id % 1000000000000) / 1000000000,
          (id % 1000000000)    / 1000000   ,
          (id % 1000000)       / 1000      ,
          (id % 1000)
        ]
      end

      def before_perform (job)
        $job_status = { 
          action:       'response',
          content_type: 'application/json',
          progress:      0
        }
        $job_status[:progress] = 0
        $redis_key             = $config[:service_id] + ':' + $args[:program_name] + ':' + job[:id]
        $validity              = job[:validity].nil? ? 300 : body[:validity].to_i
        if $config[:options] && $config[:options][:jsonapi] == true
          raise "Job didn't specify the mandatory field prefix!" if job[:prefix].blank?
          $jsonapi.set_url(job_body[:prefix])
        end
      end

      def update_progress (args)
        step     = args[:step]
        status   = args[:status]
        progress = args[:progress]
        barrier  = args[:barrier]

        if args.has_key? :message
          message_args = Hash.new
          args.each do |key, value|
            next if [:step, :progress, :message, :status, :barrier].include? key
            message_args[key] = value
          end
          message = [ args[:message], message_args ]
        else
          message = nil
        end
        $job_status[:progress] = step.nil? ? progress : ($job_status[:progress] + step.to_f).round(2)
        $job_status[:message]  = message unless message.nil?
        $job_status[:status]   = status.nil? ? 'in-progress' : status
        if args.has_key? :link
          $job_status[:link] = args[:link]
        end

        if args.has_key? :extra
          args[:extra].each do |key, value|
            $job_status[key] = value
          end
        end

        if status == 'completed' || status == 'error' || barrier
          unless barrier
            $status_timer.shutdown
          end
          $status_dirty.make_false
          update_job_status_on_redis
        elsif $status_timer.running?
          $status_dirty.make_true
        else
          update_job_status_on_redis
          $status_timer.execute
        end
      end

      def update_job_status_on_redis
        $redis.pipelined do
          redis_str = $job_status.to_json
          $redis.publish $redis_key, redis_str
          $redis.setex   $redis_key, $validity, redis_str
        end
      end

      def get_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        $jsonapi.adapter.get!(path, params, jsonapi_args)
      end

      def post_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        $jsonapi.adapter.post!(path, params, jsonapi_args)
      end

      def patch_jsonapi!(path, params, jsonapi_args)
        check_db_life_span()
        $jsonapi.adapter.patch!(path, params, jsonapi_args)
      end

      def delete_jsonapi!(path, jsonapi_args)
        check_db_life_span()
        $jsonapi.adapter.delete!(path, jsonapi_args)
      end

      def db_exec (query)
        unless query.nil?
          check_db_life_span()
          $pg.exec(query)
        end
      end

      def database_connect
        $pg.close if !$pg.nil? && !$pg.finished?
        current_url = ($jsonapi.nil? ? nil : $jsonapi.url)
        $jsonapi.close unless $jsonapi.nil?
        $pg = $jsonapi = nil
        unless $config[:postgres].nil? || $config[:postgres][:conn_str].nil?
          $pg = PG.connect($config[:postgres][:conn_str])
          # Connect to postgresql
          define_db_life_span_treshhold()
          if $config[:options][:jsonapi] == true
            $jsonapi = SP::Duh::JSONAPI::Service.new($pg, current_url)
          end
        end
      end
      
      def define_db_life_span_treshhold
        min = $config[:postgres][:min_queries_per_conn]
        max = $config[:postgres][:max_queries_per_conn]
        if (!max.nil? && max > 0) || (!min.nil? && min > 0)
          $db_life_span       = 0
          $check_db_life_span = true
          new_min, new_max = [min, max].minmax
          new_min = new_min if new_min <= 0
          if new_min + new_min > 0
            $db_treshold = (new_min + (new_min - new_min) * rand).to_i
          else
            $db_treshold = new_min.to_i
          end
        end
      end
      
      def check_db_life_span
        return unless $check_db_life_span
        $db_life_span += 1
        if $db_life_span > $db_treshold
          # Reset pg connection
          database_connect()
        end
      end

    end # Module Common
  end # Module Job
end # Module SP

# Mix-in the mix-in in the script so that we can use the Common module functions
extend SP::Job::Common

#
# Now create the global data needed by the mix-in methods
#
$redis              = Redis.new(:host => $config[:redis][:host], :port => $config[:redis][:port], :db => 0)
$progress           = 0
$check_db_life_span = false
$status_dirty       = Concurrent::AtomicBoolean.new
$status_timer       = Concurrent::TimerTask.new(execution_interval: $min_progress) do
                        if $status_dirty.true?
                          $status_dirty.make_false
                          update_job_status_on_redis
                        else
                          $status_timer.shutdown
                        end
                      end
database_connect


