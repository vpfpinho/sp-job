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

      #
      # Returns the object you should use to perform JSON api requests
      #
      # jsonapi.get! (resource, params)
      # jsonapi.post! (resource, params)
      # jsonapi.patch! (resource, params)
      # jsonapi.delete! (resource)
      #
      def jsonapi 
        $pg.check_life_span()
        $jsonapi.adapter
      end

      # 
      # You should not use this method ... unless ... you REALLY need to overide the JSON:API
      # parameters defined by the JOB object
      #
      def set_jsonapi_parameters (params)
        $jsonapi.set_jsonapi_parameters(SP::Duh::JSONAPI::ParametersNotPicky.new(params))
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
        "#{tube}:#{job[:id]}"
      end

      def prepare_job (job)
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
          $jsonapi.set_jsonapi_parameters(SP::Duh::JSONAPI::ParametersNotPicky.new(job))
        end

        # Make sure the job is still allowed to run by checking if the key exists in redis
        unless $redis.exists($job_key )
          logger.warn "Job validity has expired: job ignored"
          return false
        end



        $cancel_mutex.synchronize {
          $cancel_condition.signal
        }

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
        $job_status[:progress]    = progress.to_f.round(2) unless progress.nil?
        $job_status[:message]     = message unless message.nil?
        $job_status[:index]       = p_index unless p_index.nil?
        $job_status[:status]      = status.nil? ? 'in-progress' : status
        $job_status[:link]        = args[:link] if args[:link]
        $job_status[:status_code] = args[:status_code] if args[:status_code]

        if args.has_key? :response
          $job_status[:response]     = args[:response]
          $job_status[:content_type] = args[:content_type]
          $job_status[:action]       = args[:action]
        end

        if ['completed', 'error', 'follow-up'].include?(status) || (Time.now.to_f - $report_time_stamp) > $min_progress || args[:barrier]
          update_progress_on_redis
        end
      end

      def send_response (args)
        args[:status]       ||= 'completed'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:response]     ||= {}
        args[:status_code]  ||= 200
        update_progress(args)
        $cancel_thread.raise('rebootoh')
      end

      def report_error (args)
        args[:status] = 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 500
        update_progress(args)
        logger.error(args)
        $exception_reported = true
        $cancel_thread.raise('rebootoh')

        true
      end

      def raise_error (args)
        args[:status] = 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 500
        update_progress(args)
        logger.error(args)
        $cancel_thread.raise('rebootoh')
        
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

      def expand_mail_body (template)
        if template.class == Hash
          template_path = template[:path]
          erb_binding   = OpenStruct.new(template[:args]).instance_eval { binding }
        else
          template_path = template
          erb_binding = binding
        end

        if File.extname(template_path) == ''
          template_path += '.erb'
        end

        if template_path[0] == '/'
          erb_template = File.read(template_path)
        else
          erb_template = File.read(File.join(File.expand_path(File.dirname($PROGRAM_NAME)), template_path))
        end

        ERB.new(erb_template).result(erb_binding)
      end

      def send_email (args)
        if args.has_key?(:template) && args[:template] != nil
          email_body = expand_mail_body args[:template]
        else
          email_body = args[:body]
        end

        submit_job(
            tube:    'mail-queue',
            job: {
              to:       args[:to],
              subject:  args[:subject],
              reply_to: args[:reply_to],
              body:     email_body
            }
          )
      end

      def synchronous_send_email (args)
        if args.has_key?(:template) && args[:template] != nil
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
          reply_to (args[:reply_to] || $config[:mail][:from])

          html_part do
            content_type 'text/html; charset=UTF-8'
            body email_body
          end
        end

        if args.has_key?(:attachments)
          args[:attachments].each do |attach|
            attach_uri = URI.escape("#{attach[:protocol]}://#{attach[:host]}:#{attach[:port]}/#{attach[:path]}/#{attach[:file]}")
            attach_http_call = Curl::Easy.http_get(attach_uri)
            if attach_http_call.response_code == 200
              attributes = {}
              attach_http_call.header_str.scan(/(\w+)="([^"]*)"/).each do |group|
                attributes[group[0].to_sym] = group[1]
              end

              m.attachments[attributes[:filename].force_encoding('UTF-8')] = { mime_type: attach_http_call.content_type, content: attach_http_call.body_str }
            end
          end
        end

        m.deliver!
      end

    end # Module Common
  end # Module Job
end # Module SP
