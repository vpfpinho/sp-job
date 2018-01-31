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
require 'sp/job/pg_connection'
require 'sp/job/job_db_adapter'
require 'roadie'
require 'thread'

module SP
  module Job

    class JobCancelled < ::StandardError

    end

    class JobException < ::StandardError

      attr_reader :job
      attr_reader :args

      def initialize (args:, job: nil)
	      super(args[:message] || $current_job[:tube] || $args[:program_name])
        @job     = job
        @args    = args
      end

    end

    class Logger < ::Logger

      def task (sequence, text, success = true)
        if success
          info "[#{sequence}] #{text} \xE2\x9C\x94".green
        else
          info "[#{sequence}] #{text} \xE2\x9D\x8C".red
        end
      end
    end

  end
end


#
# Initialize global data needed for configuration
#
$prefix           = OS.mac? ? '/usr/local' : ''
$rollbar          = false
$min_progress     = 3
$args = {
  stdout:           false,
  log_level:        'info',
  program_name:     File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME)),
  config_file:      File.join($prefix, 'etc', File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME)), 'conf.json'),
  default_log_file: File.join($prefix, 'var', 'log', 'jobs', "#{File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME))}.log")
}

#
# Parse command line arguments
#
$option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} ARGS"
  opts.on('-c', '--config=CONFIG.JSON', "path to json configuration file (default: '#{$args[:default_log_file]}')") { |v| $args[:config_file] = File.expand_path(v) }
  opts.on('-l', '--log=LOGFILE'       , "path to log file (default: '#{$args[:log_file]}')")                        { |v| $args[:log_file]    = File.expand_path(v) }
  opts.on('-d', '--debug'             , "developer mode: log to stdout and print job")                              { $args[:debug]           = true                }
  opts.on('-v', '--log_level=LEVEL'   , "Log level DEBUG, INFO, WARN, ERROR, FATAL")                                { |v| $args[:log_level]   = v                   }
  opts.on('-i', '--index=IDX'         , "systemd instance index")                                                   { |v| $args[:index]       = v                   }
end
$option_parser.parse!

#
# Adjust log file if need, user specified option always takes precedence
#
if $args[:log_file].nil?
  if $args[:index].nil?
    $args[:log_file] = $args[:default_log_file]
  else
    $args[:log_file] = File.join($prefix, 'var', 'log', 'jobs', "#{$args[:program_name]}.#{$args[:index]}.log")
  end
end

#
# Create PID file for this jobs instance
#
if  OS.mac?
  Dir.mkdir("#{$prefix}/var/run/jobs") unless Dir.exist? "#{$prefix}/var/run/jobs"
end
File.write("#{$prefix}/var/run/jobs/#{$args[:program_name]}#{$args[:index].nil? ? '' : '.' + $args[:index]}.pid", Process.pid)

#
# Read configuration
#
$config = JSON.parse(File.read(File.expand_path($args[:config_file])), symbolize_names: true)
$min_progress = $config[:options][:min_progress]

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

  config.beanstalk_url = "beanstalk://#{$config[:beanstalkd][:host]}:#{$config[:beanstalkd][:port]}"
  config.on_error      = lambda { |e|
    if $exception_reported == false
      $exception_reported = true
      if e.instance_of? Beaneater::DeadlineSoonError
        logger.warn "got a deadline warning".red
      else
        begin
          raise_error(message: e)
        rescue => e
          # Do not retrow!!!!
        end
      end
    end

    # Report exception to rollbar
    if $rollbar
      if e.instance_of? ::SP::Job::JobException
        e.job[:password] = '<redacted>'
        Rollbar.error(e, e.message, { job: e.job, args: e.args})
      else
        Rollbar.error(e)
      end
    end

    # Catch fatal exception that must be handled with a restarts (systemctl will restart us)
    case e
    when PG::UnableToSend, PG::AdminShutdown, PG::ConnectionBad
      logger.fatal "Lost connection to database exiting now"
      exit
    when Redis::CannotConnectError
      logger.fatal "Can't connect to redis exiting now"
      exit
    end
  }
  config.max_job_retries  = ($config[:options] && $config[:options][:max_job_retries]) ? $config[:options][:max_job_retries] : 0
  config.retry_delay      = ($config[:options] && $config[:options][:retry_delay])     ? $config[:options][:retry_delay]     : 5
  config.retry_delay_proc = lambda { |min_retry_delay, num_retries| min_retry_delay + (num_retries ** 3) }
  config.respond_timeout  = 120
  config.default_worker   = SP::Job::Worker
  config.logger           = $args[:debug] ? SP::Job::Logger.new(STDOUT) : SP::Job::Logger.new($args[:log_file])
  config.logger.formatter = proc do |severity, datetime, progname, msg|
    date_format = datetime.strftime("%Y-%m-%d %H:%M:%S")
    "[#{date_format}] #{severity}: #{msg}\n"
  end
  if $args[:log_level].nil?
    config.logger.level = Logger::INFO
  else
    case $args[:log_level].upcase
    when 'DEBUG'
      config.logger.level = Logger::DEBUG
    when 'INFO'
      config.logger.level = Logger::INFO
    when 'WARN'
      config.logger.level = Logger::WARN
    when 'ERROR'
      config.logger.level = Logger::ERROR
    when 'FATAL'
      config.logger.level = Logger::FATAL
    else
      config.logger.level = Logger::INFO
    end
  end
  config.logger.datetime_format = "%Y-%m-%d %H:%M:%S"
  config.primary_queue          = $args[:program_name]
  config.reserve_timeout        = nil
  config.job_parser_proc        = lambda { |body|
    rv = Hash.new
    rv[:args] = [JSON.parse(body, :symbolize_names => true)]
    rv[:class] = rv[:args][0][:tube] || $args[:program_name]
    rv
  }
end

if $config[:mail]
  Mail.defaults do
    delivery_method :smtp, {
      :address => $config[:mail][:smtp][:address],
      :port => $config[:mail][:smtp][:port].to_i,
      :domain =>  $config[:mail][:smtp][:domain],
      :user_name => $config[:mail][:smtp][:user_name],
      :password => $config[:mail][:smtp][:password],
      :authentication => $config[:mail][:smtp][:authentication],
      :enable_starttls_auto => $config[:mail][:smtp][:enable_starttls_auto]
    }
  end
end

#
# Monkey patches to keep the tube name as plain vanilla job name
#
module Backburner
  module Helpers

    def expand_tube_name (tube)
      tube
    end

  end

  module Logger
    def log_job_begin(name, args)
      log_info "Work job #{name}"
      @job_started_at = Time.now
    end
  end

  class Job

    # Processes a job and handles any failure, deleting the job once complete
    #
    # @example
    #   @task.process
    #
    def process
      # Invoke the job setup function, bailout if the setup returns false
      unless job_class.respond_to?(:prepare_job) && job_class.prepare_job(*args)
        task.delete
        logger.warn "Delete stale or preempted task".red
        return false
      end

      # Invoke before hook and stop if false
      res = @hooks.invoke_hook_events(job_class, :before_perform, *args)
      unless res
        task.delete
        return false
      end
      # Execute the job
      @hooks.around_hook_events(job_class, :around_perform, *args) do
        # We subtract one to ensure we timeout before beanstalkd does, except if:
        #  a) ttr == 0, to support never timing out
        #  b) ttr == 1, so that we don't accidentally set it to never time out
        #  NB: A ttr of 1 will likely result in race conditions between
        #  Backburner and beanstalkd and should probably be avoided
        timeout_job_after(task.ttr > 1 ? task.ttr - 1 : task.ttr) { job_class.perform(*args) }
      end
      task.delete
      # Invoke after perform hook
      @hooks.invoke_hook_events(job_class, :after_perform, *args)
    rescue ::SP::Job::JobCancelled => jc
      extend SP::Job::Common # to bring.in report_error into this class
      #
      # This exception:
      #  1. is not sent to the rollbar
      #  2. does not bury the job, instead the job is deleted
      #
      Backburner.configuration.logger.info 'Received job cancellation exception'.yellow
      unless task.nil?
        Backburner.configuration.logger.debug "Task deleted".yellow
        task.delete
      end
      report_error(message: 'i18n_job_cancelled', status: 'cancelled')
      $redis.hset($job_key, 'cancelled', true) 
      $job_id = nil
    rescue => e
      @hooks.invoke_hook_events(job_class, :on_failure, e, *args)
      raise e
    end
  end
end

# Mix-in the common mix-in to make code available for the lambdas used in this file
extend SP::Job::Common

logger.debug "Log file ... #{$args[:log_file]}"
logger.debug "PID ........ #{Process.pid}"

#
# Now create the global data needed by the mix-in methods
#
$connected          = false
$job_status         = {}
$redis              = Redis.new(:host => $config[:redis][:host], :port => $config[:redis][:port], :db => 0)
$beaneater          = Beaneater.new "#{$config[:beanstalkd][:host]}:#{$config[:beanstalkd][:port]}"
$check_db_life_span = false
$status_dirty       = false
if $config[:postgres] && $config[:postgres][:conn_str]
  $pg = ::SP::Job::PGConnection.new(owner: $PROGRAM_NAME, config: $config[:postgres])
  if $config[:options][:jsonapi] == true
    $jsonapi = SP::Duh::JSONAPI::Service.new($pg, ($jsonapi.nil? ? nil : $jsonapi.url), SP::Job::JobDbAdapter)
  end
end

#
# Open a second thread that will listen to cancellation and other "signals"
#
$cancel_thread = Thread.new { 
  begin
    $subscription_redis = Redis.new(:host => $config[:redis][:host], :port => $config[:redis][:port], :db => 0)
    $subscription_redis.subscribe($config[:service_id] + ':job-signal') do |on|
      on.message do |channel, msg|
        begin
          message = JSON.parse(msg, {symbolize_names: true})
          if $job_id != nil && message[:id].to_s == $job_id && message[:status] == 'cancelled'
            logger.info "Received cancel signal for job #{$job_id}"
            Thread.main.raise(::SP::Job::JobCancelled.new)
          end
        rescue Exception => e
          # ignore invalid payloads 
        end
      end
    end
  rescue Redis::CannotConnectError => ccc
    logger.fatal "Can't connect to redis exiting now".red
    exit
  rescue Exception => e
    # Forward unexpected exceptions to the main thread for proper handling
    logger.fatal e.to_s.red
    Thread.main.raise(e)
  end
}
