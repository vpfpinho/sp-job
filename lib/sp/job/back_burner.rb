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
require 'sp/job/session'
require 'sp/job/broker'
require 'sp/job/internal_broker_exception'
require 'roadie'
require 'thread'

#
# Helper class that encapsulates the objects needed to access each cluster
#
class ClusterMember

  attr_reader :redis     # connection to cluster redis
  attr_reader :session   # access to redis session
  attr_reader :db        # database connection
  attr_reader :number    # cluster number, 1, 2 ...
  attr_reader :config    # cluster configuration read from the conf.json

  #
  # Create the cluster member wrapper
  #
  # @param configuration the cluster member configuration structure
  # @param serviceId the service prefix used by casper redis keys
  # @param db a fb connection to reuse or nil if a new one should be created
  #
  def initialize (configuration:, serviceId:, db: nil)
    @redis = Redis.new(:host => configuration[:redis][:casper][:host], :port => configuration[:redis][:casper][:port], :db => 0)
    @session = ::SP::Job::Session.new(configuration: configuration, serviceId: serviceId, redis: @redis, programName: $args[:program_name])
    if db.nil?
      if $config[:options] && $config[:options][:post_connect_queries]
        configuration[:db][:post_connect_queries] =  $config[:options][:post_connect_queries]
      end
      @db = ::SP::Job::PGConnection.new(owner: 'back_burner', config: configuration[:db])
    else
      @db = db
    end
    @number = configuration[:number]
    @config = configuration
  end

  #
  # Returns the global logger object, borrowed from common.rb
  #
  def self.logger
    Backburner.configuration.logger
  end

  #
  # Creates the global structure that contains the cluster configuration
  #
  def self.configure_cluster
    $cluster_members = {}

    $config[:cluster][:members].each do |cfg|
      next if !cfg[:exclude_member].nil? && cfg[:exclude_member] == true
      cfg[:db][:conn_str] = pg_conn_str(cfg[:db])
      if cfg[:number] == $config[:runs_on_cluster]
        if $cluster_config
          $cluster_config[:db][:conn_str] = cfg[:db][:conn_str]
        end
        $cluster_members[cfg[:number]] = ClusterMember.new(configuration: cfg, serviceId: $config[:service_id], db: $pg)
      else
        $cluster_members[cfg[:number]] = ClusterMember.new(configuration: cfg, serviceId: $config[:service_id])
      end
      logger.info "Cluster member #{cfg[:number]}: #{cfg[:url]} db=#{cfg[:db][:host]}:#{cfg[:db][:port]}(#{cfg[:db][:dbname]}) redis=#{cfg[:redis][:casper][:host]}:#{cfg[:redis][:casper][:port]}#{' <=' if cfg[:number] == $config[:runs_on_cluster]}"
    end
  end

end


module SP
  module Job

    class JobCancelled < ::StandardError

    end

    class JobAborted < ::StandardError
    end

    class JobException < ::StandardError

      attr_reader :job
      attr_reader :args

      def initialize (args:, job: nil)
	      super(args[:message] || $args[:program_name])
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

    class ThreadData < Struct.new(:job_status, :report_time_stamp, :exception_reported, :job_id, :publish_key, :job_key, :current_job, :job_notification, :jsonapi, :job_tube, :notification_lock, :notification_lock_key, :tube_options)
      def initialize
        self.job_status = {}
      end
    end

    class FauxMutex
      def synchronize (&block)
        yield
      end
    end

  end
end

#
# Helper to build BG connection strings
#
def pg_conn_str (config, app_name = nil)
  if app_name.nil?
    app_name = "application_name=#{$args[:program_name]}"
  end
  return "host=#{config[:host]} port=#{config[:port]} dbname=#{config[:dbname]} user=#{config[:user]}#{config[:password] && config[:password].size != 0 ? ' password='+ config[:password] : '' } #{app_name}"
end

#
# Initialize global data needed for configuration
#
$prefix           = OS.mac? ? '/usr/local' : ''
$rollbar          = false
$gracefull_exit   = false
$args = {
  stdout:           false,
  log_level:        'info',
  program_name:     File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME)),
  config_file:      File.join($prefix, 'etc', 'jobs', 'main.conf.json'),
  default_log_file: File.join($prefix, 'var', 'log', 'jobs', "#{File.basename($PROGRAM_NAME, File.extname($PROGRAM_NAME))}.log")
}

#
# Parse command line arguments
#
$option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} ARGS"
  opts.on('-c', '--config=CONFIG.JSON', "path to json configuration file (default: '#{$args[:config_file]}')") { |v| $args[:config_file] = File.expand_path(v) }
  opts.on('-l', '--log=LOGFILE'       , "path to log file (default: '#{$args[:default_log_file]}')")           { |v| $args[:log_file]    = File.expand_path(v) }
  opts.on('-d', '--debug'             , "developer mode: log to stdout and print job")                         { $args[:debug]           = true                }
  opts.on('-v', '--log_level=LEVEL'   , "Log level DEBUG, INFO, WARN, ERROR, FATAL")                           { |v| $args[:log_level]   = v                   }
  opts.on('-i', '--index=IDX'         , "systemd instance index")                                              { |v| $args[:index]       = v                   }
end
$option_parser.parse!

if $args[:debug]
  require 'ruby-debug' if RUBY_ENGINE == 'jruby'
end

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

#
# Monkey patches the sad reality of ruby development
#
if RUBY_ENGINE == 'jruby'

  class Logger
    class LogDevice

      def write(message)
        begin
          synchronize do
            if @shift_age and @dev.respond_to?(:stat)
              begin
                check_shift_log
              rescue
                warn("log shifting failed. #{$!}")
              end
            end
            begin
              @dev.write(message)
            rescue ::SP::Job::JobCancelled => jc
              raise jc
            rescue
              warn("log writing failed. #{$!}")
            end
          end
        rescue ::SP::Job::JobCancelled => jc
          raise jc
        rescue Exception => ignored
          warn("log writing failed. #{ignored}")
        end
      end

    end
  end
end

module Backburner
  module Helpers

    def expand_tube_name (tube)
      tube
    end

  end

  module Logger

    def log_job_begin(name, args)
      param_log = ''
      args = args[0]
      [ :user_id, :entity_id, :entity_schema, :sharded_schema, :subentity_id, :subentity_prefix, :subentity_schema, :action].each do |key|
        if args.has_key?(key) && !(args[key].nil? || args[key].empty?)
          param_log += "#{key}: #{args[key]},"
        end
      end
      log_info "Job ##{args[:id]} started #{name}: #{param_log}".white
      Thread.current[:job_started_at] = Time.now
    end

    # Print out when a job completed
    # If message is nil, job is considered complete
    def log_job_end(name, message = nil)
      ellapsed = Time.now - Thread.current[:job_started_at]
      ms = (ellapsed.to_f * 1000).to_i
      action_word = message ? 'finished' : 'completed'
      log_info "Job ##{$thread_data[Thread.current][:current_job][:id]} #{action_word} (#{name}) in #{ms}ms #{message}".white
    end

  end

  class Job
    include SP::Job::Common # to bring in logger and report_error into this class

    # Processes a job and handles any failure, deleting the job once complete
    #
    # @example
    #   @task.process
    #
    def process
      td = thread_data

      # Invoke the job setup function, bailout if the setup returns false
      unless job_class.respond_to?(:prepare_job) && job_class.prepare_job(*args)
        logger.warn "Delete stale or preempted task".red

        # Signal job termination and remove from queue
        td.job_id = nil
        task.delete
        return false
      end

      # Invoke before hook and stop if false
      res = @hooks.invoke_hook_events(job_class, :before_perform, *args)
      @hooks.invoke_hook_events(job_class, :prepend_platform_configuration, *args)
      unless res
        # Signal job termination and remove from queue
        td.job_id = nil
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
        if task.stats.nil?
          ttr = 60 # Experimental
        elsif task.ttr > 1
          ttr = task.ttr - 1
        else
          ttr = task.ttr
        end

        timeout_job_after(ttr) { job_class.perform(*args) }
      end
      task.delete
      # Invoke after perform hook
      @hooks.invoke_hook_events(job_class, :after_perform, *args)
      # ensure currently open ( if any ) transaction rollback
      $pg.rollback unless ! $pg
    rescue ::SP::Job::JobAborted
      #
      # This exception:
      #  1. is sent to the rollbar
      #  2. does not bury the job, instead the job is deleted
      #
      unless task.nil?
        task.delete
      end
      # Invoke after perform hook
      @hooks.invoke_hook_events(job_class, :after_perform, *args)
      td.job_id = nil
      # ensure currently open ( if any ) transaction rollback
      $pg.rollback unless ! $pg
    rescue ::SP::Job::JobCancelled => jc
      #
      # This exception:
      #  1. is not sent to the rollbar
      #  2. does not bury the job, instead the job is deleted
      #
      logger.info "Received job cancellation exception #{Thread.current}".yellow
      unless task.nil?
        logger.info 'Task deleted'.yellow
        begin
          task.delete
        rescue Beaneater::NotFoundError => bnfe
          @hooks.invoke_hook_events(job_class, :on_failure, bnfe, *args)
        end
      end
      @hooks.invoke_hook_events(job_class, :on_failure, jc, *args)
      error_handler(message: 'i18n_job_cancelled', status: 'cancelled')
      if $redis_mutex.nil?
        $redis.hset(td.job_key, 'cancelled', true)
      else
        $redis_mutex.synchronize {
          $redis.hset(td.job_key, 'cancelled', true)
        }
      end
      td.job_id = nil
      # ensure currently open ( if any ) transaction rollback
      $pg.rollback unless ! $pg
    rescue => e
      # ensure currently open ( if any ) transaction rollback

      if $pg
        $pg.rollback
        if e.is_a?(Backburner::Job::JobTimeout)
          logger.info 'RESET PG connection because Backburner::Job::JobTimeout could be inside PG'.red
          $pg.connect()
        end
      end

      # if we're in broker mode
      if td.tube_options[:broker] == true
        # prepare next action for this exception
        exception_options = {
          bury: td.tube_options[:bury],
          raise: true
        }
        begin
          tmp = InternalBrokerException.handle(task: task, exception: e, hooks: { klass: job_class, var:@hooks }, callback: method(:send_response))
          exception_options[:bury]  = tmp.has_key?(:bury)  ? tmp[:bury]  : exception_options[:bury]
          exception_options[:raise] = tmp.has_key?(:raise) ? tmp[:raise] : exception_options[:raise]
        rescue => ne
          @hooks.invoke_hook_events(job_class, :on_failure, ne, *args)
          raise ne
        end
        # delete it now?
        if nil != task
          if true == exception_options[:bury]
            task.bury
          else
            task.delete
          end
        end
        # re-raise?
        if true == exception_options[:raise]
          raise e
        end
      else
        @hooks.invoke_hook_events(job_class, :on_failure, e, *args)
        raise e
      end
      # Signal job termination
      td.job_id = nil
    end
  end

end

# Mix-in the common mix-in to make code available for the lambdas used in this file
extend SP::Job::Common

#
# Now create the global data needed by the mix-in methods
#
$connected     = false

# Unified configuration (now it's always unified)
if $config[:jobs][$args[:program_name].to_sym] && $config[:jobs][$args[:program_name].to_sym][:runs_on]
  $cluster_config = $config[:cluster][$config[:jobs][$args[:program_name].to_sym][:runs_on].to_sym]
else
  $cluster_config = $config[:cluster][:members].find{ |clt| clt[:number] == $config[:runs_on_cluster] }
end

if $config[:jobs][$args[:program_name].to_sym] && $config[:jobs][$args[:program_name].to_sym][:options]
  $config[:options] = $config[:jobs][$args[:program_name].to_sym][:options]
else
  $config[:options] = {}
end

if $config.has_key?(:paths) && $config[:paths].has_key?(:private_key)
  key_name = $config[:nginx_broker][:private_key] if $config[:nginx_broker].has_key?(:private_key)
  key_name ||= 'nginx-broker'

  $config[:nginx_broker_private_key] = "#{$config[:paths][:private_key]}/#{key_name}"
end

# Get current member database configuration
$redis          = Redis.new(:host => $cluster_config[:redis][:casper][:host], :port => $cluster_config[:redis][:casper][:port], :db => 0)
$verbose_log   = $config[:options] && $config[:options][:verbose_log] == true
$beaneater     = Beaneater.new "#{$cluster_config[:beanstalkd][:host]}:#{$cluster_config[:beanstalkd][:port]}"
if $cluster_config[:db]
  $cluster_config[:db][:conn_str] = pg_conn_str($cluster_config[:db])
  if $config[:options] && $config[:options][:post_connect_queries]
    $cluster_config[:db][:post_connect_queries] =  $config[:options][:post_connect_queries]
  end
  $pg = ::SP::Job::PGConnection.new(owner: $args[:program_name], config: $cluster_config[:db], multithreaded: $multithreading)
  if $verbose_log
    $pg.exec("SET log_min_duration_statement TO 0;")
  end
end

 $beanstalk_url = "beanstalk://#{$cluster_config[:beanstalkd][:host]}:#{$cluster_config[:beanstalkd][:port]}"

#
# Sanity check we only support multithreading on JRUBY
#
if $config[:options] && $config[:options][:threads].to_i > 1
  raise 'Multithreading is not supported in MRI/CRuby' unless RUBY_ENGINE == 'jruby'
  $redis_mutex = Mutex.new
  $roolbar_mutex = Mutex.new
  $multithreading = true
else
  $redis_mutex = nil
  $roolbar_mutex = ::SP::Job::FauxMutex.new
  $multithreading = false
end

#
# Configure rollbar
#
unless $config[:rollbar].nil?

  if $config[:rollbar][:enabled] == false
    $rollbar = false
  else
    $rollbar = true
  end

  Rollbar.configure do |config|
    config.access_token = $config[:rollbar][:token] if $config[:rollbar][:token]
    config.environment  = $config[:rollbar][:environment] if $config[:rollbar] && $config[:rollbar][:environment]
  end
end

Backburner.configure do |config|

  config.beanstalk_url = $beanstalk_url
  config.on_error      = lambda { |e|
    td = thread_data

    # ensure currently open ( if any ) transaction rollback
    $pg.rollback unless ! $pg

    if td.exception_reported == false
      td.exception_reported = true
      if e.instance_of? Beaneater::DeadlineSoonError
        logger.warn "got a deadline warning".red
      else
        begin
          if td.tube_options[:broker] == true
            send_response(InternalBrokerException.translate_to_response(e:e))
          else
            if e.is_a?(::SP::Job::JobAborted) || e.is_a?(::SP::Job::JobException)
              raise_error(message: e)
            else
              raise_error(message: 'i18n_unexpected_server_error')
            end
          end
        rescue
          # Do not retrow!!!!
        end
      end
    end
    # Report exception to rollbar
    $roolbar_mutex.synchronize {
      if $rollbar
        if e.instance_of? ::SP::Job::JobException
          e.job[:password] = '<redacted>'
          Rollbar.error(e, e.message, { job: e.job, args: e.args})
        elsif e.is_a?(::SP::Job::JSONAPI::Error)
          Rollbar.error(e, e.body)
        else
          Rollbar.error(e)
        end
      end
    }

    # Signal job termination
    td.job_id = nil

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
  config.default_worker   = $config[:options] && $config[:options][:threads].to_i > 1 ? SP::Job::WorkerThread : SP::Job::Worker
  config.logger           = $args[:debug] ? SP::Job::Logger.new(STDOUT) : SP::Job::Logger.new($args[:log_file])
  config.logger.formatter = proc do |severity, datetime, progname, msg|
    date_format = datetime.strftime("%Y-%m-%d %H:%M:%S")
    "[#{date_format}] #{severity}: #{msg}\n"
  end

  logger.info "Log file ...... #{$args[:log_file]}"
  logger.info "PID ........... #{Process.pid}"


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

#### TODO end ####

# Check if the user DB is on a different database
if config[:cluster]
  if config[:cluster][:cdb].instance_of? Hash
    config[:cluster][:cdb][:conn_str] = pg_conn_str(config[:cluster][:cdb])
    $cdb = ::SP::Job::PGConnection.new(owner: $PROGRAM_NAME, config: config[:cluster][:cdb], multithreaded: $multithreading)
    logger.info "Central DB .... #{$cdb.config[:host]}:#{$cdb.config[:port]}(#{$cdb.config[:dbname]})"
  else
    $cdb = nil # Will be grabbed from $cluster_members
    logger.info "Central DB .... embedded in cluster #{config[:cluster][:cdb]}"
  end
end

$excluded_members = $config[:cluster].nil? || $config[:cluster][:members].nil? ? [] : ( $config[:cluster][:members].map {|m| m[:number] if m[:exclude_member] }.compact )

#
# Global data for mutex and sync
#
$threads = [ Thread.current ]
$thread_data = {}
$thread_data[Thread.current] = ::SP::Job::ThreadData.new

#
# Signal handler
#
Signal.trap('SIGUSR2') {
  $gracefull_exit = true
  check_gracefull_exit(dolog: false)
}

#
# Open a second thread that will listen to cancellation and other "signals"
#
$cancel_thread = Thread.new {
  begin
    host = $cluster_config && $cluster_config[:redis][:casper][:host] || $config[:redis][:host]
    port = $cluster_config && $cluster_config[:redis][:casper][:port] || $config[:redis][:port]
    $subscription_redis = Redis.new(:host => host, :port => port, :db => 0)
    $subscription_redis.subscribe($config[:service_id] + ':job-signal') do |on|
      on.message do |channel, msg|
        begin
          message = JSON.parse(msg, {symbolize_names: true})
          $threads.each do |thread|
            if $thread_data[thread].job_id != nil && message[:id].to_s == $thread_data[thread].job_id.to_s && message[:status] == 'cancelled'
              logger.info "Received cancel signal for job #{$thread_data[thread].job_id}"
              thread.raise(::SP::Job::JobCancelled.new)
            end
          end
        rescue Exception
          # ignore invalid payloads
        end
      end
    end
  rescue Redis::CannotConnectError
    logger.fatal "Can't connect to redis exiting now".red
    exit
  rescue Exception => e
    # Forward unexpected exceptions to the main thread for proper handling
    logger.fatal e.to_s.red
    Thread.main.raise(e)
  end
}
