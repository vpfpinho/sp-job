#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
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
module SP
  module Job
    module Common

      def http (oauth_client_id:, oauth_client_secret:)
  
        $http_oauth_clients ||= {}
        $http_oauth_clients[oauth_client_id] ||= ::SP::Job::BrokerHTTPClient.new(
                  a_session =  ::SP::Job::BrokerHTTPClient::Session.new(
                                  a_access_token  = nil,
                                  a_refresh_token = nil,
                                  a_scope         = $config[:api][:oauth][:scope]
                                ),
                  a_oauth2_client = ::SP::Job::BrokerOAuth2Client.new(
                    protocol:      $config[:api][:oauth][:protocol],
                    host:          $config[:api][:oauth][:host],
                    port:          $config[:api][:oauth][:port],
                    client_id:     oauth_client_id,
                    client_secret: oauth_client_secret,
                    redirect_uri:  $config[:api][:oauth][:redirect_uri],
                    scope:         $config[:api][:oauth][:scope],
                    options:       {}
                  ),
                  a_refreshed_callback = method(:refreshed_callback),
                  a_auto_renew_refresh_token = true
        )
        $http_oauth_clients[oauth_client_id]
      end

      #
      # Called by BrokerHTTPClient when a new session was created
      # or an older one was refreshed.
      #
      def refreshed_callback(a_session)
        logger.task('#', "Session #{a_session.is_new ? 'created' : 'refreshed' }, access_token=#{a_session.access_token}, refresh_token=#{a_session.refresh_token}")
      end

      def db
        $pg
      end

      def config
        $config
      end

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

      def submit_job (args)
        job      = args[:job]
        tube     = args[:tube] || $args[:program_name]
        raise 'missing job argument' unless args[:job]

        validity = args[:validity] || 180
        ttr      = args[:ttr]      || 60
        job[:id] = ($redis.incr "#{$config[:service_id]}:jobs:sequential_id").to_s
        job[:tube] = tube
        job[:validity] = validity
        redis_key = "#{$config[:service_id]}:jobs:#{tube}:#{job[:id]}"
        $redis.pipelined do
          $redis.hset(redis_key, 'status', '{"status":"queued"}')
          $redis.expire(redis_key, validity)
        end
        $beaneater.tubes[tube].put job.to_json, ttr: ttr
      end

      def prepare_job (job)
        if $connected == false && $config[:postgres]
          database_connect
          $redis.get "#{$config}:jobs:sequential_id" # For what ??
          $connected = true
        end

        $current_job = job
        $job_status = {
          action:       'response',
          content_type: 'application/json',
          progress:      0
        }
        $report_time_stamp     = 0
        $job_status[:progress] = 0
        $exception_reported    = false
        $publish_key           = $config[:service_id] + ':' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        $job_key               = $config[:service_id] + ':jobs:' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        $validity              = job[:validity].nil? ? 300 : job[:validity].to_i
        if $config[:options] && $config[:options][:jsonapi] == true
          raise "Job didn't specify the mandatory field prefix!" if job[:prefix].blank?
          $jsonapi.set_url(job[:prefix])
          init_params = {}
          init_params[:user_id] = job[:user_id] unless job[:user_id].blank?
          init_params[:company_id] = job[:company_id] unless job[:company_id].blank?
          init_params[:company_schema] = job[:company_schema] unless job[:company_schema].blank?
          init_params[:sharded_schema] = job[:sharded_schema] unless job[:sharded_schema].blank?
          init_params[:accounting_prefix] = job[:accounting_prefix] unless job[:accounting_prefix].blank?
          init_params[:accounting_schema] = job[:accounting_schema] unless job[:accounting_schema].blank?

          $jsonapi.set_jsonapi_parameters(SP::Duh::JSONAPI::Parameters.new(init_params))
        end

        # Make sure the job is still allowed to run by checking if the key exists in redis
        unless $redis.exists($job_key )
          logger.warn "Job validity has expired: job ignored"
          return false
        end
        return true
      end

      #
      # Optionally after the jobs runs sucessfully clean the "job" key in redis
      # 
      def after_perform_cleanup (job)
        if false # TODO check key namings with americo $job key and redis key
          return if $redis.nil?
          return if $job_key.nil?
          $redis.del $job_key
        end
      end

      def update_progress (args)
        status   = args[:status]
        progress = args[:progress]
        p_index  = args[:index]

        if args.has_key? :message
          message_args = Hash.new
          args.each do |key, value|
            next if [:step, :progress, :message, :status, :barrier, :index, :response, :action, :content_type, :status_code, :link].include? key
            message_args[key] = value
          end
          message = [ args[:message], message_args ]
        else
          message = nil
        end
        $job_status = {}
        $job_status[:progress] = progress.to_f.round(2) unless progress.nil?
        $job_status[:message]  = message unless message.nil?
        $job_status[:index]    = p_index unless p_index.nil?
        $job_status[:status]   = status.nil? ? 'in-progress' : status
        $job_status[:link]     = args[:link] if args[:link]

        if args.has_key? :response
          $job_status[:response]     = args[:response]
          $job_status[:content_type] = args[:content_type]
          $job_status[:status_code]  = args[:status_code]
          $job_status[:action]       = args[:action]
        end

        if status == 'completed' || status == 'error' || (Time.now.to_f - $report_time_stamp) > $min_progress || args[:barrier]
          update_progress_on_redis
        end
      end

      def send_response (args)
        args[:status]         = 'completed'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:response]     ||= {}
        args[:status_code]  ||= 200
        update_progress(args)
      end

      def report_error (args)
        args[:status] = 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 200
        update_progress(args)
        logger.error(args)
        $exception_reported = true
        true
      end

      def raise_error (args)
        args[:status] = 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 200
        update_progress(args)
        logger.error(args)
        $exception_reported = true
        raise ::SP::Job::JobException.new(args: args, job: $current_job)
      end

      def update_progress_on_redis
        $redis.pipelined do
          redis_str = $job_status.to_json
          $redis.publish $publish_key, redis_str
          $redis.hset    $job_key, 'status', redis_str
          $redis.expire  $job_key, $validity
        end
        $report_time_stamp = Time.now.to_f
      end

      def get_jsonapi!(path, params)
        check_db_life_span()
        $jsonapi.adapter.get!(path, params)
      end

      def post_jsonapi!(path, params)
        check_db_life_span()
        $jsonapi.adapter.post!(path, params)
      end

      def patch_jsonapi!(path, params)
        check_db_life_span()
        $jsonapi.adapter.patch!(path, params)
      end

      def delete_jsonapi!(path)
        check_db_life_span()
        $jsonapi.adapter.delete!(path)
      end

      def expand_mail_body (template)
        if File.extname(template) == ''
          template += '.erb'
        end
        if template[0] == '/'
          erb_template = File.read(template)
        else
          erb_template = File.read(File.join(File.expand_path(File.dirname($PROGRAM_NAME)), template))
        end
        ERB.new(erb_template).result(binding)
      end

      def send_mail (args)
        if args.has_key?(:template)
          email_body = expand_mail_body args[:template]
        else
          email_body = args[:body]
        end
        submit_job(
            tube:    'mail-queue',
            to:      job[:to],
            subject: job[:subject],
            body:    email_body
          )
      end

      def synchronous_send_email (args)
        if args.has_key?(:template)
          email_body = expand_mail_body args[:template]
        else
          email_body = args[:body]
        end

        document = Roadie::Document.new email_body
        email_body = document.transform

        m = Mail.new do
          from     $config[:mail][:from]
          to       args[:to]
          subject  args[:subject]

          html_part do
            content_type 'text/html; charset=UTF-8'
            body email_body
          end
        end

        m.deliver!
      end

      def database_connect
        # any connection to close?
        if ! $jsonapi.nil?
          $jsonapi.close
          $jsonapi = nil
        end
        if nil != $pg
          $pg.disconnect()
          $pg = nil
        end
        # establish new connection?
        if $config[:postgres] && $config[:postgres][:conn_str]
          $pg = ::SP::Job::PGConnection.new(owner: 'back_burner', config: $config[:postgres])
          $pg.connect()
          if $config[:options][:jsonapi] == true
            $jsonapi = SP::Duh::JSONAPI::Service.new($pg.connection, ($jsonapi.nil? ? nil : $jsonapi.url))
          end
        end
      end

      # TODO move this out of here by forcing json api to use new class made by americo
      def define_db_life_span_treshhold
        min = $config[:postgres][:min_queries_per_conn]
        max = $config[:postgres][:max_queries_per_conn]
        if (!max.nil? && max > 0) || (!min.nil? && min > 0)
          $db_life_span       = 0
          $check_db_life_span = true
          new_min, new_max = [min, max].minmax
          new_min = new_min if new_min <= 0
          if new_min + new_min > 0
            $db_treshold = (new_min + (new_max - new_min) * rand).to_i
          else
            $db_treshold = new_min.to_i
          end
        end
      end

      # TODO move this out of here by forcing json api to use new class made by americo
      def check_db_life_span
        return unless $check_db_life_span
        $db_life_span += 1
        if $db_life_span > $db_treshold
          # Reset pg connection
          database_connect()
        end
      end

      # TODO remove and replace all calls with db.exec
      def db_exec (query)
        $pg.query(query: query)
      end


    end # Module Common
  end # Module Job
end # Module SP
