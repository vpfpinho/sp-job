# coding: utf-8
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

      def prepend_platform_configuration (job)
        begin
          if config && config[:brands] && job && job[:x_brand]
            @platform_configuration = config[:brands][job[:x_brand].to_sym][:"platform-configuration"]
            @color_scheme           = config[:brands][job[:x_brand].to_sym][:"color-scheme"]
          end
        rescue Exception => e
          raise 'No Platform Configuration'
        end
      end

      def exclude_member(member_number)
        $excluded_members.include? member_number
      end

      def thread_data
        $thread_data[Thread.current]
      end

      def http (oauth_client_id:, oauth_client_secret:, oauth_client_host: nil, oauth_client_redirect_uri: nil)

        $http_oauth_clients ||= {}
        $http_oauth_clients[oauth_client_id] ||= ::SP::Job::BrokerHTTPClient.new(
                  a_session =  ::SP::Job::BrokerHTTPClient::Session.new(
                                  a_access_token  = nil,
                                  a_refresh_token = nil,
                                  a_scope         = $config[:api][:oauth][:scope]
                                ),
                  a_oauth2_client = ::SP::Job::BrokerOAuth2Client.new(
                    protocol:      $config[:api][:oauth][:protocol],
                    host:          oauth_client_host || $config[:api][:oauth][:host],
                    port:          $config[:api][:oauth][:port],
                    client_id:     oauth_client_id,
                    client_secret: oauth_client_secret,
                    redirect_uri:  oauth_client_redirect_uri || $config[:api][:oauth][:redirect_uri],
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

      def user_db
        if $user_db.nil?
          $user_db = $cluster_members[config[:cluster][:user_db]].db
        end
        $user_db
      end

      def main_bo_db
        if $main_bo_db.nil?
          $main_bo_db = $cluster_members[config[:cluster][:main_bo_db]].db
        end
        $main_bo_db
      end

      def redis
        # callback is not optional
        if $redis_mutex.nil?
          yield($redis)
        else
          # ... to enforce safe usage!
          $redis_mutex.synchronize {
            yield($redis)
          }
        end
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

      def has_jsonapi
        return thread_data.jsonapi != nil
      end

      #
      # You should not use this method ... unless ... you REALLY need to overide the JSON:API
      # parameters defined by the JOB object
      #
      def set_jsonapi_parameters (params)
        if RUBY_ENGINE == 'jruby'  # TODO suck in the base class from SP-DUH
          thread_data.jsonapi.set_jsonapi_parameters(SP::JSONAPI::ParametersNotPicky.new(params))
        else
          thread_data.jsonapi.set_jsonapi_parameters(SP::Duh::JSONAPI::ParametersNotPicky.new(params))
        end
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
      #   1. config[:scp_config][:local] true if this machine is also the upload server
      #   2. config[:scp_config][:local] name of upload host with ssh access
      #   3. config[:scp_config][:path] base path of for file uploads server on the local or remote machine
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
        if config[:scp_config][:local] == true
          destination_file = ::SP::Job::Unique::File.create(File.join(config[:scp_config][:path], remote_path), extension)
          FileUtils.cp(src_file, destination_file)
        else
          uploads_server = config[:scp_config][:server]
          destination_file = %x[ssh #{uploads_server} unique-file -p #{File.join(config[:scp_config][:path], remote_path)} -e #{extension[1..-1]}].strip
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
      # Retrieve a previously uploaded file.
      #
      # @param file
      # @param tmp_dir
      #
      # @return When tmp_dir is set file URI otherwise file body.
      #
      def get_from_upload_server(file:, tmp_dir:, alt_path: nil)
        path = alt_path.nil? ? config[:tmp_file_server][:path] + '/' : alt_path
        response = HttpClient.get_klass.get(url: "#{config[:tmp_file_server][:protocol]}://#{config[:tmp_file_server][:server]}:#{config[:tmp_file_server][:port]}/#{path}#{file}")
        if 200 != response[:code]
          raise "#{response[:code]}"
        end
        if tmp_dir
          uri = Unique::File.create("/tmp/#{(Date.today + 2).to_s}", 'dl')
          File.open(uri, 'wb') {
             |f| f.write(response[:body])
          }
          uri
        else
          response[:body]
        end
      end

      #
      # Send a file from the webservers to a permanent location in the file server by http
      #
      # @param file_name
      # @param src_file
      # @param content_type
      # @param access
      # @param company_id
      # @param user_id      
      #
      def send_to_file_server(file_name: '', src_file:, content_type:, access:, billing_type:, billing_id:, company_id: nil, user_id: nil)

        raise 'missing argument user_id/company_id' if user_id.nil? && company_id.nil?

        url = "#{config[:internal_file_server][:protocol]}://#{config[:internal_file_server][:server]}:#{config[:internal_file_server][:port]}/#{config[:internal_file_server][:path]}"

        headers = {
          'Content-Type' => content_type.to_s,
          'X-CASPER-ACCESS' => access.to_s,
          'X-CASPER-FILENAME' => "#{file_name.force_encoding('ISO-8859-1')}",
          'X-CASPER-ARCHIVED-BY' => 'sp-job',
          'X-CASPER-BILLING-TYPE' => billing_type.to_s,
          'X-CASPER-BILLING-ID' => billing_id.to_s
        }

        if !company_id.nil? && user_id.nil?
          headers['X-CASPER-ENTITY-ID'] = "#{company_id.to_s}"
        elsif company_id.nil? && !user_id.nil?
          headers['X-CASPER-USER-ID'] = "#{user_id.to_s}"
        else
          headers['X-CASPER-USER-ID'] = "#{user_id.to_s}"
        end

        file = File.open(src_file, "rb")
        contents = file.read
        file.close

        response = HttpClient.get_klass.post(
          url: url,
          headers: headers,
          body: contents,
          expect: {
            code: 200,
            content: {
              type: 'application/vnd.api+json;charset=utf-8'
            }
          }
        )

        if 200 != response[:code]
          raise "#{response[:code]}"
        end

        JSON.parse(response[:body])        

      end

      #
      # Move a file from uploads/tmp to a permanent location in the file server
      #
      # @param tmp_file
      # @param final_file
      # @param content_type
      # @param access
      # @param user_id
      # @param company_id
      #
      def move_to_file_server(tmp_file:, final_file: '', content_type:, access:, billing_type:, billing_id:, user_id: nil, company_id: nil)

        raise 'missing argument user_id/company_id' if user_id.nil? && company_id.nil?

        url = "#{config[:internal_file_server][:protocol]}://#{config[:internal_file_server][:server]}:#{config[:internal_file_server][:port]}/#{config[:internal_file_server][:path]}"

        headers = {
          'Content-Type' => content_type.to_s,
          'X-CASPER-ACCESS' => access.to_s,
          'X-CASPER-MOVES-URI' => tmp_file.to_s,
          'X-CASPER-FILENAME' => "#{final_file.force_encoding('ISO-8859-1')}",
          'X-CASPER-ARCHIVED-BY' => 'sp-job',
          'X-CASPER-BILLING-TYPE' => billing_type.to_s,
          'X-CASPER-BILLING-ID' => billing_id.to_s
        }

        if !company_id.nil? && user_id.nil?
          headers['X-CASPER-ENTITY-ID'] = "#{company_id.to_s}"
        elsif company_id.nil? && !user_id.nil?
          headers['X-CASPER-USER-ID'] = "#{user_id.to_s}"
        else
          headers['X-CASPER-USER-ID'] = "#{user_id.to_s}"
        end

        response = HttpClient.get_klass.post(
          url: url,
          headers: headers,
          body: '',
          expect: {
            code: 200,
            content: {
              type: 'application/vnd.api+json;charset=utf-8'
            }
          }
        )

        if 200 != response[:code]
          raise "#{response[:code]}"
        end

        JSON.parse(response[:body])

      end

      #
      # Delete a file in the file server
      #
      # @param file_identifier
      # @param user_id
      # @param entity_id
      # @param role_mask
      # @param module_mask
      #
      def delete_from_file_server (file_identifier:, user_id:, entity_id:, role_mask:, module_mask:, billing_type:, billing_id:)

        raise 'missing file_identifier' if file_identifier.nil?

        url = "#{config[:internal_file_server][:protocol]}://#{config[:internal_file_server][:server]}:#{config[:internal_file_server][:port]}/#{config[:internal_file_server][:path]}/#{file_identifier}"

        headers = {          
          'X-CASPER-USER-ID' => user_id.to_s,
          'X-CASPER-ENTITY-ID' => entity_id.to_s,
          'X-CASPER-ROLE-MASK' => role_mask.to_s,
          'X-CASPER-MODULE-MASK' => module_mask.to_s,
          'USER-AGENT' => 'sp-job',
          'X-CASPER-BILLING-TYPE' => billing_type.to_s,
          'X-CASPER-BILLING-ID' => billing_id.to_s
        }

        response = HttpClient.get_klass.delete(
          url: url,
          headers: headers          
        )

        if 204 != response[:code]
          raise "#{response[:code]}"
        end
      end

      #
      # Submit jwt
      #
      def submit_jwt (url, jwt)
        response = HttpClient.get_klass.post(
          url: url,
          headers: {
            'Content-Type' => 'application/text'
          },
          body: jwt,
          expect: {
            code: 200,
            content: {
              type: 'application/json'
            }
          }
        )
        response
      end

      #
      # Create a role mask given an array of roles
      #
      def get_role_mask (role_names)
        roles = db.exec(%Q[
          SELECT name, mask
            FROM public.roles
        ])
        roles = roles.inject({}){|n_hash, db_hash| n_hash.merge({db_hash['name'] => db_hash['mask']}) }

        res = roles[role_names[0]].to_i
        role_names.shift
        role_names.each do |name|
          res = (res | roles[name].to_i)
        end

        "0x#{sprintf("%04x", res)}"
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

      def get_next_job_id
        ($redis.incr "#{$config[:service_id]}:jobs:sequential_id").to_s
      end

      def _submit_job (args)
        job      = args[:job]
        tube     = args[:tube] || $args[:program_name]
        raise 'missing job argument' unless args[:job]

        validity = args[:validity] || 180
        ttr      = args[:ttr]      || 60
        job[:id] ||= get_next_job_id
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
        td.job_tube             = (job[:tube] || $args[:program_name])
        if has_jsonapi
          set_jsonapi_parameters(job)
        end

        # Make sure the job is still allowed to run by checking if the key exists in redis
        exists = redis do |r|
          r.exists(td.job_key)
        end
        unless exists
          # Signal job termination
          td.job_id = nil
          logger.warn 'Job validity has expired: job ignored'.yellow
          return false
        end

        # Make sure the job was not explicity cancelled
        cancelled = redis do |r|
          r.hget(td.job_key, 'cancelled')
        end
        if cancelled == 'true'
          td.job_id = nil
          logger.warn 'Job was explicity cancelled'.yellow
          return false
        end

        return true
      end

      def update_progress (args)
        td = thread_data
        status              = args[:status]
        progress            = args[:progress]
        p_index             = args[:index] || 0
        notification_title  = args[:title]
        p_options           = args[:options]

        if args.has_key? :message
          message_args = Hash.new
          args.each do |key, value|
            next if [:step, :progress, :message, :status, :barrier, :index, :response, :action, :content_type, :status_code, :link, :custom].include? key
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
        td.job_status[:message]     = message unless message.nil?

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
        [:status_code, :custom, :link].each do |key|
          td.job_notification[key] = args[key] if args[key]
        end
        if args.has_key? :response
          td.job_notification[:response]     = args[:response]
          td.job_notification[:content_type] = args[:content_type]
          td.job_notification[:action]       = args[:action]
        end

        if ['completed', 'error', 'follow-up', 'cancelled'].include?(status) || (Time.now.to_f - td.report_time_stamp) > $min_progress || args[:barrier]
          update_progress_on_redis
          if td.current_job[:notification]
            notification_icon   = p_options && p_options[:icon] || td.current_job[:notification_options] && td.current_job[:notification_options][:icon] ||  "toc-icons:notification_SIS"
            notification_link   = p_options && p_options[:link] || td.current_job[:notification_options] && td.current_job[:notification_options][:link] ||  ""
            notification_remote = p_options && p_options[:remote] || td.current_job[:notification_options] && td.current_job[:notification_options][:remote] || false
            notification_title  = notification_title || p_options && p_options[:title] || td.current_job[:notification_options] && td.current_job[:notification_options][:title] || td.current_job[:notification_title] ||  "Notification title"

            message = {
              dismiss: ['completed', 'error', 'follow-up', 'cancelled', 'imported'].include?(status),
              can_be_canceled: !['completed', 'error', 'follow-up', 'cancelled', 'imported'].include?(status),
              status: status || td.job_notification[:status],
              icon: notification_icon,
              link: notification_link,
              title: notification_title,
              updated_at: Time.new,
              per_user: false,
              remote: notification_remote,
              tube: td.job_tube,
              id: [td.job_tube, td.job_id].join(":"),
              identity: td.job_id,
              content: p_options && p_options[:message] || td.job_notification[:message]
            }

            if td.current_job[:notification_options] 
              message.merge!({
                wizard: td.current_job[:notification_options][:wizard],
                wizard_options: td.current_job[:notification_options][:wizard_options]
              }) if td.current_job[:notification_options][:wizard] && td.current_job[:notification_options][:wizard_options]

              message.merge!({
                expiration_date: td.current_job[:notification_options][:expiration_date]
              }) if td.current_job[:notification_options][:expiration_date]
            end

            notification_options = {
              service: $config[:service_id],
              entity: 'company',
              entity_id: td.current_job[:entity_id],
              action: :update
            }

            manage_notification(notification_options, message)
          end
        end
      end

      def send_response (args)
        td = thread_data
        args[:status]       ||= 'completed'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:response]     ||= {}
        args[:status_code]  ||= 200
        # $raw_response cam either be:
        # - a Boolean (true or false)
        # - an Array of tube names; in this case, the response is raw if the current tube name is one of the Array names
        is_raw_response = ($raw_response.is_a?(Array) ? td.job_tube.in?($raw_response) : $raw_response)
        if is_raw_response && $transient_job || args[:force_raw_response]
          response = '*'
          response << args[:status_code].to_s
          response << ','
          response << args[:content_type].bytesize.to_s
          response << ','
          response << args[:content_type]
          response << ','
          if args[:response].instance_of? String
            args[:response] = args[:response].force_encoding('utf-8')
            response << args[:response].bytesize.to_s
            response << ','
            response << args[:response]
          elsif args[:response].instance_of? StringIO
            if 'application/json' == args[:content_type]
              raw = args[:response].string.force_encoding('utf-8')
            else
              raw = args[:response].string
            end
            response << raw.size.to_s
            response << ','
            response << raw
          else
            if args[:response].is_a?(Hash)
              if args[:response].has_key?(:errors) && args[:response][:errors].is_a?(Array)
                args[:response][:errors].each do | e |
                  if e.has_key?(:detail)
                    e[:detail] = e[:detail].force_encoding('utf-8')
                  end
                end
              end
            end
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
        signal_job_termination(td)
        td.job_id = nil
      end

      def on_bury_lock_cleanup(*args)
        #logger.error "Caused an exception (#{args.to_s})"
      end

      def on_failure_lock_cleanup(e, *args)
        #logger.error "Lock cleanup caused an exception (#{e})"
      end

      def on_failure_for_all_jobs(e, *args)
        begin
          job = thread_data.current_job

        _message = if (e.is_a?(::SP::Job::JobAborted))
            eval(e.message)[:args][:message]
          else
            self.pg_server_error(e) || _notification
          end

          report_error(progress: 100, status: 'error', message: _message, detail: "Error in job with params: #{job} -> #{e}" )
        rescue => e
          logger.error "**** FAILURE ALL JOBS **** #{e}"
        end
        
      end

      def after_perform_lock_cleanup (*args)
        check_gracefull_exit(dolog: true)
      end

      def check_gracefull_exit (dolog: false)
        if $gracefull_exit
          jobs = 0
          $thread_data.each do |thread, thread_data|
            unless thread_data.job_id.nil?
              jobs += 1
            end
          end
          if jobs == 0
            message =  'SIGUSR2 requested no jobs are running exiting now'
            if dolog
              logger.info message
            else
              puts message
            end
            $beaneater.close
            exit 0
          else
            message = "SIGUSR2 requested but #{jobs} jobs are still running"
            if dolog
              logger.info message
            else
              puts message
            end
          end
        end
      end

      def error_handler (args)
        if $config[:options][:source] == "broker"
          raise "Implementation error : please use 'raise' instead of report_error or raise_error"
        end
        td = thread_data
        args[:status]       ||= 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 500
        update_progress(args)
        logger.error(args)
        td.exception_reported = true
        signal_job_termination(td)
        td.job_id = nil
      end

      #
      # @NOTE: do not use this method if $config[:options][:source] == "broker"
      #
      def report_error (args)
        td = thread_data
        error_handler(args)
        raise ::SP::Job::JobAborted.new(args: args, job: td.current_job)
      end

      #
      # @NOTE: do not use this method if $config[:options][:source] == "broker"
      #
      def raise_error (args)
        td = thread_data
        if ! args.is_a? Hash
          raise "'args' must be an Hash!"
        end
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

      def signal_job_termination (td)
        redis do |r|
          r.publish $config[:service_id] + ':job-signal', { channel: td.publish_key, id: td.job_id.to_i, status: 'finished' }.to_json
        end
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

      def manage_notification_worker(options = {}, notification = {})

        if options[:redis]
          redis_client_master = options[:redis]
        end

        raise 'Can do anything without redis connection on redis_client_master' unless redis_client_master

        queues      = redis_client_master.smembers("resque:queues")
        queue_type  = notification[:type]
        c_id        = notification[:company_id]
        n_id        = notification[:resource_id]

        queue_len = redis_client_master.llen("resque:queue:#{queue_type}")
        redis_client_master.lrange("resque:queue:#{queue_type}", 0, queue_len)
        match_string = "[#{c_id},#{n_id}]"
        rem_command = redis_client_master.lrange("resque:queue:#{queue_type}", 0, queue_len).find do |queue_find|
          queue_find.include?(match_string)
        end

        # ap ["notification", notification, "queues", queues, queue_type, c_id, n_id, "rem_command", rem_command]

        if rem_command
          puts "queue_type => #{queue_type} :::: rem_command => #{rem_command}".red
          redis_client_master.lrem("resque:queue:#{queue_type}", "-2", rem_command)
        end

      end


      def manage_notification(options = {}, notification = {})

        options = {
          service: "toconline",
          type: 'notifications',
          action: :new
        }.merge(options)

        if options[:redis]
          redis_client = options[:redis]
        else
          redis_client = $redis
        end

        redis_key = {
          key: [options[:service], options[:type], options[:entity], options[:entity_id]].join(":"),
          public_key: [options[:service], options[:entity], options[:entity_id]].join(":")
        }

        if options[:action] == :new

          response_object = notification

          job_type  = notification[:tube] && notification[:tube].gsub("-hd", "") #remove the -hd pattern to merge on the original tube ex: saft-importer-hd -> saft-importer
          
          job_exists = redis_client.sscan(redis_key[:key], 0, { match: "*\"tube\":\"#{job_type}*\"*" }) if job_type

          unless job_exists
            job_exists = redis_client.sscan(redis_key[:key], 0, { match: "*\"icon\":\"#{notification[:icon]}\"*\"resource_job_queue_name\":\"#{notification[:resource_job_queue_name]}*" })
          end

          if job_exists[1] && job_exists[1].any?
            job_exists[1].map do |key|
              redis_client.srem redis_key[:key], "#{key}"
              temp_response_object = { id: JSON.parse(key)["id"], destroy: true }
              redis_client.publish redis_key[:public_key], "#{temp_response_object.to_json}"
            end
            # ap ["theres a similar job notification => REDIS PUBLISH DESTROY", redis_key[:public_key], temp_response_object.to_json]

            # ap ["create the new one after destroy similar"]
            redis_client.sadd redis_key[:key], "#{notification.to_json}"
            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
          else
            redis_client.sadd redis_key[:key], "#{notification.to_json}"
            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
          end

        elsif options[:action] == :update

          match_member = redis_client.sscan(redis_key[:key], 0, { match: "*#{notification[:id]}\"*" })

          if match_member && match_member[1][0]

            notification.merge!({id: notification[:id]}) if notification[:id]
            response_object = notification

            redis_client.srem redis_key[:key], "#{match_member[1][0]}"
            notification.delete(:identity)
            redis_client.sadd redis_key[:key], "#{notification.to_json}"

            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
            # ap ["REDIS PUBLISH UPDATE", redis_key[:public_key], response_object.to_json]

          else
            # puts 'nothing to update [[better insert]]'
            manage_notification(
              options.merge({action: :new}),
              notification
            )
          end
        else

          match_member = redis_client.sscan(redis_key[:key], 0, { match: "*#{notification[:identity]}\"*" })
          if match_member && match_member[1].any?
            response_object = { id: notification[:identity], destroy: true } if notification[:identity]
            redis_client.srem redis_key[:key], "#{match_member[1][0]}"
            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
          else
            puts 'nothing to destroy'
          end

        end

      end

      def email_addresses_valid? (email_addresses)
        begin
          raise ::ArgumentError.new 'A lista de emails tem de estar preenchida' if email_addresses.nil? || email_addresses.empty?

          email_addresses = email_addresses.split(',').map(&:strip)
          valid_email_addresses = email_addresses.select { |email| !email.match(RFC822::EMAIL).nil? }
          diff_email_addresses = email_addresses - valid_email_addresses

          raise ::Exception.new "Os seguintes endereços de email não são válidos: #{diff_email_addresses.join(', ')}" if diff_email_addresses.length > 0

          return { valid: true }
        rescue ::Exception => e
          return {
            valid: false,
            error: {
              type: e.class,
              message: e.message
            },
            invalid_emails: diff_email_addresses
          }
        end
      end

      def sanitize_email_addresses! (email_addresses)
        email_addresses.split(',').map { |email| email.strip.downcase }.join(', ')
      end

      def send_email (args)

        if args.has_key?(:body) && args[:body] != nil
          email_body = args[:body]
        elsif args.has_key?(:template) && args[:template] != nil
          email_body = expand_mail_body args[:template]
        end

        ___internal=nil
        if args.has_key?(:___internal) && nil != args[:___internal]
          ___internal = args[:___internal]
        end

        submit_job(
            tube: args[:'mail-queue-tube'] || 'mail-queue',
            job: {
              to:       args[:to],
              subject:  args[:subject],
              reply_to: args[:reply_to],
              body:     email_body,
              ___internal: ___internal
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

        to_email = config[:override_mail_recipient] if config[:override_mail_recipient]
        to_email ||= args[:to]

        response_errors = {}

        to_emails_validation = email_addresses_valid?(to_email)
        unless to_emails_validation[:valid]
          response_errors[:mailto] = to_emails_validation[:error][:message]
          response_errors[:mailto_invalid] = to_emails_validation[:invalid_emails]
        end

        # Do not send email to Cc if there is an override_mail_recipient
        cc_email = nil
        cc_email ||= args[:cc] if !args[:cc].nil? && config[:override_mail_recipient].nil?

        if !cc_email.nil?
          cc_emails_validation = email_addresses_valid?(cc_email)
          unless cc_emails_validation[:valid]
            response_errors[:mailcc] = cc_emails_validation[:error][:message]
            response_errors[:mailcc_invalid] = cc_emails_validation[:invalid_emails]
          end
        end

        if response_errors.length != 0
          report_error(message: 'invalidEmails', status_code: 400, response: response_errors)
          return
        end

        m = Mail.new do
          from     $config[:mail][:from]
          to       to_email
          cc       cc_email unless cc_email.nil?
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
            if false == args[:session].nil? && false == args[:session][:role_mask].nil?
              uri += "/#{attach[:id]}"
              attach_http_call = Curl::Easy.http_get(URI.escape(uri)) do |http|
                http.headers['X-CASPER-USER-ID'] = args[:session][:user_id]
                http.headers['X-CASPER-ENTITY-ID'] = args[:session][:entity_id]
                http.headers['X-CASPER-ROLE-MASK'] = args[:session][:role_mask]
                http.headers['X-CASPER-MODULE-MASK'] = args[:session][:module_mask]
                http.headers['User-Agent'] = "curb/mail-queue"
              end
            else
              uri += "/#{attach[:file]}" if attach.has_key?(:file) && !attach[:file].nil?
              attach_http_call = Curl::Easy.http_get(URI.escape(uri))
            end
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
            else
              raise "synchronous_send_email: #{attach_http_call.response_code} - #{uri}"
            end
          end
        end

        m.deliver!
      end

      def pg_server_error (e)
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

      def get_percentage (total: 1, count: 0) ; (total > 0 ? (count * 100 / total) : count).to_i ; end

      def on_retry_job (count, delay, jobs)
        td = thread_data
        new_delay = jobs[:validity].to_i + (delay.to_i * count)
        $redis.expire(td.job_key, new_delay)
      end

      def print_and_archive (payload, entity_id)
        payload[:ttr]            ||= 300
        payload[:validity]       ||= 500
        payload[:auto_printable] ||= false
        payload[:documents]      ||= []

        jwt = JWTHelper.jobify(
          key: config[:nginx_broker_private_key],
          tube: 'casper-print-queue',
          payload: payload
        )

        pdf_response = HttpClient.get_klass.post(
          url: get_cdn_public_url,
          headers: {
            'Content-Type' => 'application/text'
          },
          body: jwt,
          expect: {
            code: 200,
            content: {
              type: 'application/pdf'
            }
          },
          conn_options: {
            connection_timeout: payload[:ttr],
            request_timeout: payload[:ttr]
          }
        )

        tmp_file = Unique::File.create("/tmp/#{(Date.today + 2).to_s}", ".pdf")
        File.open(tmp_file, 'wb') { |f| f.write(pdf_response[:body]) }
        file_identifier = send_to_upload_server(src_file: tmp_file, id: entity_id, extension: ".pdf")
        file_identifier
      end

      def print_and_archive_http (payload:, entity_id:, access:, file_name: '', billing_type:)
        payload[:ttr]            ||= 300
        payload[:validity]       ||= 500
        payload[:auto_printable] ||= false
        payload[:documents]      ||= []

        jwt = JWTHelper.jobify(
          key: config[:nginx_broker_private_key],
          tube: 'casper-print-queue',
          payload: payload
        )

        pdf_response = HttpClient.get_klass.post(
          url: get_cdn_public_url,
          headers: {
            'Content-Type' => 'application/text'
          },
          body: jwt,
          expect: {
            code: 200,
            content: {
              type: 'application/pdf'
            }
          },
          conn_options: {
            connection_timeout: payload[:ttr],
            request_timeout: payload[:ttr]
          }
        )

        tmp_file = Unique::File.create("/tmp/#{(Date.today + 2).to_s}", ".pdf")
        File.open(tmp_file, 'wb') { |f| f.write(pdf_response[:body]) }

        response = send_to_file_server(file_name: file_name, 
                                       src_file: tmp_file, 
                                       content_type: 'application/pdf', 
                                       access: access,  
                                       billing_type: billing_type, 
                                       billing_id: entity_id, 
                                       company_id: entity_id)
        response
      end

      class Exception < StandardError

        private

        @status_code  = nil
        @content_type = nil
        @body         = nil

        public
        attr_accessor :status_code
        attr_accessor :content_type
        attr_accessor :body

        public
        def initialize(status_code:, content_type:, body:)
          @status_code  = status_code
          @content_type = content_type
          @body         = body
        end

      end # class Error

      private

      def get_random_folder
        ALPHABET[rand(26)] + ALPHABET[rand(26)]
      end

      def get_cdn_public_url
        cdn_public_url = "#{config[:broker][:cdn][:protocol]}://#{config[:broker][:cdn][:host]}"
        if config[:broker][:cdn][:port] && 80 != config[:broker][:cdn][:port]
        	cdn_public_url += ":#{config[:broker][:cdn][:port]}"
        end
        if config[:broker][:cdn][:path]
        	cdn_public_url += "/#{config[:broker][:cdn][:path]}"
        end
        cdn_public_url
      end

    end # Module Common
  end # Module Job
end # Module SP
