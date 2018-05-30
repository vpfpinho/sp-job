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

      ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

      def thread_data
        $thread_data[Thread.current]
      end

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

      def redis
        $redis
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
        thread_data.jsonapi.adapter
      end

      #
      # You should not use this method ... unless ... you REALLY need to overide the JSON:API
      # parameters defined by the JOB object
      #
      def set_jsonapi_parameters (params)
        thread_data.jsonapi.set_jsonapi_parameters(SP::Duh::JSONAPI::ParametersNotPicky.new(params))
      end

      #
      # You should not use this method ... unless ... you REALLY need to overide the JSON:API
      # parameters defined by the JOB object
      #
      def get_jsonapi_parameters
        HashWithIndifferentAccess.new(JSON.parse(thread_data.jsonapi.parameters.to_json))
      end

      #
      # returns the logger object that job code must use for logging
      #
      def logger
        Backburner.configuration.logger
      end

      #
      # Uploads a local file to the resting location on the upload server via the internal network
      #
      # Note the upload server could be the same machine, in that case we just copy the file. When the
      # server is a remote machine it must grant ssh access to this machine and have the program unique-file
      # in the path of ssh user
      #
      # Also make sure the job using this method has the following configuration parameers
      #   1. config[:uploads][:local] true if this machine is also the upload server
      #   2. config[:uploads][:local] name of upload host with ssh access
      #   3. config[:uploads][:path] base path of for file uploads server on the local or remote machine
      #
      # @param src_file name of local file to upload
      # @param id entity id user_id or company_id
      # @param extension filename extension with the . use '.pdf' not 'pdf'
      # @param entity can be either 'user' or 'company'
      # @param folder two letter subfolder inside entity folder use '00' for temp files
      #
      def send_to_upload_server (src_file:, id:, extension:, entity: 'company', folder: nil)
        folder ||= get_random_folder
        remote_path = File.join(entity, id_to_path(id.to_i), folder)
        if config[:uploads][:local] == true
          destination_file = ::SP::Job::Unique::File.create(File.join(config[:uploads][:path], remote_path), extension)
          FileUtils.cp(src_file, destination_file)
        else
          uploads_server = config[:uploads][:server]
          destination_file = %x[ssh #{uploads_server} unique-file -p #{File.join(config[:uploads][:path], remote_path)} -e #{extension[1..-1]}].strip
          if $?.exitstatus == 0
            %x[scp #{src_file} #{uploads_server}:#{destination_file}]
            raise_error(message: 'i18n_upload_to_server_failed') if $?.exitstatus != 0
          else
            raise_error(message: 'i18n_upload_to_server_failed')
          end
        end

        return entity[0] + folder + destination_file[-(6+extension.length)..-1]
      end

      #
      # Submit job to beanstalk queue
      #
      # Mandatory (symbolized) keys in args:
      #
      # 1. :job arbritary job data, must be a hash but can contatined nested data
      #
      # Optional keys in args:
      #
      def submit_job (args)
        if $redis_mutex.nil?
          rv = _submit_job(args)
        else
          $redis_mutex.synchronize {
            rv = _submit_job(args)
          }
        end
        rv
      end

      def _submit_job (args)
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
        logger.debug "Preparing job id #{job[:id]}".green

        td = thread_data
        td.current_job = job
        td.job_status = {
          content_type: 'application/json',
          progress: [
            {
              message: nil,
              value: 0
            }
          ]
        }
        td.report_time_stamp    = 0
        td.exception_reported   = false
        td.job_id               = job[:id]
        td.publish_key          = $config[:service_id] + ':' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        td.job_key              = $config[:service_id] + ':jobs:' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        if $config[:options] && $config[:options][:jsonapi] == true && !job[:prefix].blank?
          td.jsonapi.set_url(job[:prefix])
          set_jsonapi_parameters(job)
        end

        # Make sure the job is still allowed to run by checking if the key exists in redis
        unless $redis.exists(td.job_key)
          logger.warn "Job validity has expired: job ignored".yellow
          return false
        end
        return true
      end

      def update_progress (args)
        td = thread_data
        status   = args[:status]
        progress = args[:progress]
        p_index  = args[:index] || 0

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

        # update job status
        if p_index >= td.job_status[:progress].size
          (1 + p_index - td.job_status[:progress].size).times do
            td.job_status[:progress] << { message: nil, value: 0 }
          end
        end
        unless message.nil?
          td.job_status[:progress][p_index][:message] = message
        end
        unless progress.nil?
          td.job_status[:progress][p_index][:value] = progress.to_f.round(2)
        end
        td.job_status[:status]      = status.nil? ? 'in-progress' : status
        td.job_status[:link]        = args[:link] if args[:link]
        td.job_status[:status_code] = args[:status_code] if args[:status_code]
        if args.has_key? :response
          td.job_status[:response]     = args[:response]
          td.job_status[:content_type] = args[:content_type]
          td.job_status[:action]       = args[:action]
        end

        # Create notification that will be published
        td.job_notification = {}
        td.job_notification[:progress]    = progress.to_f.round(2) unless progress.nil?
        td.job_notification[:message]     = message unless message.nil?
        td.job_notification[:index]       = p_index unless p_index.nil?
        td.job_notification[:status]      = status.nil? ? 'in-progress' : status
        td.job_notification[:link]        = args[:link] if args[:link]
        td.job_notification[:status_code] = args[:status_code] if args[:status_code]
        if args.has_key? :response
          td.job_notification[:response]     = args[:response]
          td.job_notification[:content_type] = args[:content_type]
          td.job_notification[:action]       = args[:action]
        end

        if ['completed', 'error', 'follow-up', 'cancelled'].include?(status) || (Time.now.to_f - td.report_time_stamp) > $min_progress || args[:barrier]
          update_progress_on_redis
        end
      end

      def send_response (args)
        td = thread_data
        args[:status]       ||= 'completed'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:response]     ||= {}
        args[:status_code]  ||= 200
        if $raw_response && $transient_job
          response = '*'
          response << args[:status_code].to_s
          response << ','
          response << args[:content_type].bytesize.to_s
          response << ','
          response << args[:content_type]
          response << ','
          if args[:response].instance_of? String
            response << args[:response].bytesize.to_s
            response << ','
            response << args[:response]
          elsif args[:response].instance_of? StringIO
            raw = args[:response].string
            response << raw.bytesize.to_s
            response << ','
            response << raw
          else
            json = args[:response].to_json
            response << json.bytesize.to_s
            response << ','
            response << json
          end
          if $redis_mutex.nil?
            $redis.publish td.publish_key, response
          else
            $redis_mutex.synchronize {
              $redis.publish td.publish_key, response
            }
          end
        else
          update_progress(args)
        end
        td.job_id = nil
      end

      def error_handler (args)
        td = thread_data
        args[:status]       ||= 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 500
        update_progress(args)
        logger.error(args)
        td.exception_reported = true
        td.job_id = nil
      end

      def report_error (args)
        td = thread_data
        error_handler(args)
        raise ::SP::Job::JobAborted.new(args: args, job: td.current_job)
      end

      def raise_error (args)
        td = thread_data
        error_handler(args)
        raise ::SP::Job::JobException.new(args: args, job: td.current_job)
      end

      def update_progress_on_redis
        td = thread_data
        if $redis_mutex.nil?
          if $transient_job
            $redis.publish td.publish_key, td.job_notification.to_json
          else
            $redis.pipelined do
              $redis.publish td.publish_key, td.job_notification.to_json
              $redis.hset    td.job_key, 'status', td.job_status.to_json
            end
          end
        else
          $redis_mutex.synchronize {
            if $transient_job
              $redis.publish td.publish_key, td.job_notification.to_json
            else
              $redis.pipelined do
                $redis.publish td.publish_key, td.job_notification.to_json
                $redis.hset    td.job_key, 'status', td.job_status.to_json
              end
            end
          }
        end
        td.report_time_stamp = Time.now.to_f
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

        if args.has_key?(:body) && args[:body] != nil
          email_body = args[:body]
        elsif args.has_key?(:template) && args[:template] != nil
          email_body = expand_mail_body args[:template]
        end

        submit_job(
            tube: 'mail-queue',
            job: {
              to:       args[:to],
              subject:  args[:subject],
              reply_to: args[:reply_to],
              body:     email_body
            }
          )
      end

      def synchronous_send_email (args)

        if args.has_key?(:body) && args[:body] != nil
          email_body = args[:body]
        elsif args.has_key?(:template) && args[:template] != nil
          email_body = expand_mail_body args[:template]
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

        if args.has_key?(:attachments) && args[:attachments] != nil
          args[:attachments].each do |attach|
            uri = "#{attach[:protocol]}://#{attach[:host]}:#{attach[:port]}/#{attach[:path]}"
            uri += "/#{attach[:file]}" if attach.has_key?(:file) && !attach[:file].nil?

            attach_uri = URI.escape(uri)
            attach_http_call = Curl::Easy.http_get(attach_uri)
            if attach_http_call.response_code == 200
              attributes = {}

              if attach.has_key?(:filename)
                attributes[:filename] = attach[:filename]
                attributes[:mime_type] = attach[:mime_type]
              else
                attach_http_call.header_str.scan(/(\w+)="([^"]*)"/).each do |group|
                  attributes[group[0].to_sym] = group[1]
                end
                attributes[:mime_type] = attach_http_call.content_type
              end

              m.attachments[attributes[:filename].force_encoding('UTF-8').gsub('±', ' ')] = { mime_type: attributes[:mime_type], content: attach_http_call.body_str }
            end
          end
        end

        m.deliver!
      end

      def pg_server_error(e)
        raise e if e.is_a?(::SP::Job::JobCancelled)
        base_exception = e
        while base_exception.respond_to?(:cause) && !base_exception.cause.blank?
          base_exception = base_exception.cause
        end

        return base_exception.is_a?(PG::ServerError) ? base_exception.result.error_field(PG::PG_DIAG_MESSAGE_PRIMARY) : e.message
      end

      def file_identifier_to_url(id, filename)
        url = ''
        if filename[0] == 'c'
          url += "company"
        elsif filename[0] == 'u'
          url += "user"
        else
          raise 'Unrecognizible file type'
        end

        url += '/'
        url += id_to_path(id)
        url += '/'
        url += filename[1..2]
        url += '/'
        url += filename[3..-1]
        url
      end

      #
      # Converts and id to a four level folder hierarchy
      #
      # @param id entity id must be an integer
      # @return the path
      #
      def id_to_path (id)
        "%03d/%03d/%03d/%03d" % [
          (id % 1000000000000) / 1000000000,
          (id % 1000000000)    / 1000000   ,
          (id % 1000000)       / 1000      ,
          (id % 1000)
        ]
      end

      def get_percentage(total: 1, count: 0) ; (total > 0 ? (count * 100 / total) : count).to_i ; end

      def on_retry_job (count, delay, jobs)
       td = thread_data
       new_delay = jobs[:validity].to_i + (delay.to_i * count)
       $redis.expire(td.job_key, new_delay)
       # puts "INITIAL #{jobs[:validity]} / DELAY #{delay} ==> NEW validity #{new_delay} | #{count}".red
     end

      private

      def get_random_folder
        ALPHABET[rand(26)] + ALPHABET[rand(26)]
      end
    end # Module Common
  end # Module Job
end # Module SP
