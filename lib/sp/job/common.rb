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

      include SP::Job::Lock

      ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

      class Exception < StandardError

        attr_accessor :status_code
        attr_accessor :content_type
        attr_accessor :body

        def initialize(status_code:, content_type: nil, body: nil)
          @status_code  = status_code
          @content_type = content_type
          @body         = body
        end

      end # class Exception

      #
      # These are default per tube options 'tube classes' can overide tube_options() to merge with these values
      #
      def default_tube_options
        { broker: false, transient: false, raw_response: false, min_progress: 3, bury: true, disconnect_db: false, simpleapi: false }
      end

      #
      # Returns object with the platform definitions taking into account the brand(ing)
      #
      def platform_configuration
        td = thread_data
        unless td.platform_configuration
          load_platform_configuration(td)
        end
        td.platform_configuration
      end

      #
      # Returns color schema taking into account the brand(ing)
      #
      def color_scheme
        td = thread_data
        unless td.color_scheme
          load_platform_configuration(td)
        end
        td.color_scheme
      end

      #
      # Lazily load color scheme and platform spec into thread data
      #
      # Give priority to the brand key patched from session data, if that fails fallback to x_brand inserted by the front-end
      #
      def load_platform_configuration (thread_data)
        begin
          if config && config[:brands]
            brand = thread_data.current_job[:brand] || thread_data.current_job[:x_brand] || config[:product]
            unless brand.nil?
              thread_data.platform_configuration = config[:brands][brand.to_sym][:'platform-configuration']
              thread_data.color_scheme           = config[:brands][brand.to_sym][:'color-scheme']
            end
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

      # Warning this method will be deprecated!!!!
      def user_db
        if $cdb.nil?
          $cdb = $cluster_members[config[:cluster][:cdb]].db
        end
        $cdb
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

      def cluster_config
        $cluster_config
      end

      #
      # Returns the public application URL for the given brand and cluster
      #
      # @param brand - the brand needed if the machine suports multiple brands
      # @param cluster - the cluster number defaults to current cluster
      #
      def app_url (brand: nil, cluster: nil)
        brand   ||= config[:product]
        cluster ||= config[:runs_on_cluster]
        url = $app_urls[brand+cluster.to_s]
        if url.nil?
          url = $config[:urls][:brands][brand.to_sym][:app_url].sub('<cluster>', cluster.to_s)
          $app_urls[brand+cluster.to_s] = url
        end
        url
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
        td = thread_data
        if td.jsonapi.nil?
          require 'sp/job/job_db_adapter' # TODO suck in the base class from SP-DUH
          unless Kernel.const_defined?("::SP::Duh")
            td.jsonapi = SP::JSONAPI::Service.new($pg, 'https://jsonapi.developer.com', SP::Job::JobDbAdapter)
          else
            # TODO this needs sp-duh to be "manually" required in MRI
            td.jsonapi = SP::Duh::JSONAPI::Service.new($pg, 'https://jsonapi.developer.com', SP::Job::JobDbAdapter)
          end
        end
        set_jsonapi_parameters(td.current_job)
        td.jsonapi.adapter
      end

      #
      # You should not use this method ... unless ... you REALLY need to overide the JSON:API
      # parameters defined by the JOB object
      #
      def set_jsonapi_parameters (params)
        unless Kernel.const_defined?("::SP::Duh")  # TODO suck in the base class from SP-DUH
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
        JSON.parse(thread_data.jsonapi.parameters.to_json, symbolize_names: true)
      end


      #
      # Ensure a CDB API client per thread and initialize it with current job.
      #
      def cdb_api
        td = thread_data
        if td.cdb_api.nil?
          td.cdb_api = ::SP::Job::CentralApiClient.new(owner: self, url: config[:urls][:cdb_api], job: td.current_job)
        else
          td.cdb_api.set(job: td.current_job)
        end
        td.cdb_api
      end

      #
      # Ensure a CDB Vault API client per thread and initialize it with current job.
      #
      def vault_api
        td = thread_data
        if td.vault_api.nil?
          td.vault_api = CdbVaultClient.new(owner: self, url: config[:urls][:cdb_api], job: td.current_job)
        else
          td.vault_api.set(job: td.current_job)
        end
        td.vault_api
      end

      #
      # Ensure a CDN Archive Sideline API client per thread and initialize it with current job.
      #
      def cdn_sideline
        td = thread_data
        if td.cdn_sideline.nil?
          td.cdn_sideline = ::SP::Job::BrokerArchiveClient::SidelineAPIClient.new(owner: self.name(), url: "#{config[:urls][:fs_api_internal]}")
        end
        td.cdn_sideline
      end

      #
      # Ensure there is only one BrokerArchiveClient per thread
      #
      def broker_archive_client
        td = thread_data
        if td.broker_archive_client.nil?
          td.broker_archive_client = ::SP::Job::BrokerArchiveClient.new(owner: td.job_tube, url: config[:urls][:archive_internal], job: nil)
        else
          td.broker_archive_client.reset(owner: td.job_tube, job: td.current_job)
        end
        td.broker_archive_client
      end

      #
      # returns the logger object that job code must use for logging
      #
      def logger
        Backburner.configuration.logger
      end

      def send_to_rollbar(exception:, level: :error)
        td = thread_data
        # Report exception to rollbar
        $roolbar_mutex.synchronize {
          if $rollbar
            begin
              extra_params = {}
              if exception.instance_of? ::SP::Job::JobException
                exception.job[:password] = '<redacted>'
                extra_params.merge!({ job: exception.job, args: exception.args}) if exception.job
                Rollbar.send(level, exception, exception.message, extra_params)
              elsif exception.is_a?(::SP::Job::JSONAPI::Error)
                extra_params.merge!({ job: td.current_job }) if td && td.current_job
                Rollbar.send(level, exception, exception.body, extra_params)
              elsif exception.is_a?(::SP::Job::EasyHttpClient::Error)
                extra_params.merge!({ job: td.current_job }) if td && td.current_job
                Rollbar.send(level, exception, exception.status, extra_params)
              else
                extra_params.merge!({ job: td.current_job }) if td && td.current_job
                Rollbar.send(level, exception, exception.message, extra_params)
              end
            rescue => e
              logger.error "Unable to call Rollbar.error: #{e}"
              e.backtrace.each_with_index do | l, i |
                logger.error "%3s %1s%s%s %s" % [ ' ', '['.white, i.to_s.rjust(3, ' ').white, ']'.white , l.yellow ]
              end
          end
          end
        }
      end

      #
      # Rollbar or log a message.
      #
      # @param owner     Who owns this object.
      # @param tube      Tube where error occurred.
      # @param message Message to log.
      # @param params  Extra params to log.
      #
      def rollbar_and_raise(message:, owner:, tube:, exception:)
        if $rollbar
          Rollbar.error("#{owner} // #{tube} // #{message}", exception)
        end
        raise exception
      end

      #
      # Retrieve a unique file on tmp/DATE folder. This files are automatically erased after days_after time.
      #
      # @param days_after
      # @param extension
      #
      # @return unique file URI for a file on tmp/DATE.
      #
      def get_unique_file(tmp_dir: 'tmp', days_after: 2, name: nil, extension: '')
        Unique::File.create_n(folder: "/#{tmp_dir}/#{(Date.today + days_after).strftime('%Y-%m-%d')}", name: name, extension: extension)
      end

      #
      # Retrieve the cdn internal link for a file on tmp/DATE folder.
      #
      # @param path
      #
      # @return cdn internal link for the file
      #
      def get_cdn_internal_for(path)
        "#{config[:urls][:cdn_internal]}/#{path.split('/')[-2..-1].join('/')}"
      end

      #
      # Retrieve the cdn internal link for a file on tmp/DATE folder, based on th respective template and variables.
      #
      # @param path
      #
      # @return cdn internal link for the file
      #
      def cdn_for_template(template, variables)
        get_cdn_internal_for(get_tmp_file_for_template(template, variables))
      end

      #
      # Creates and loads a tmp file based on the template and respective variables
      #
      # @param path
      #
      # @return tmp file path generated
      #
      def get_tmp_file_for_template (template, variables)
        tempfile = File.open(get_unique_file(extension: '.eml'), 'wb')
        tempfile.write load_content_from_template(template, variables)
        tempfile.flush
        tempfile.close
        tempfile.path
      end

      #
      # Loads the content for a specific template
      #
      # @param content based on a template and respective variables.
      #
      # @return content binded between a template and respective variables
      #
      def load_content_from_template (template, variables)
        template = ERB.new(File.read(template))
        erb_binding = OpenStruct.new(variables).instance_eval { binding }
        template.result(erb_binding)
      end

      #
      # Retrieve a previously uploaded public ( company or user ) file .
      #
      # @param file
      # @param tmp_dir
      #
      # @return When tmp_dir is set file URI otherwise file body.
      #
      def get_public_file(file:, tmp_dir:, alt_path: nil)
        get_from_temporary_uploads(file: file, tmp_dir: tmp_dir, alt_path: alt_path)
      end

      #
      # Retrieve a previously temporary uploaded file.
      #
      # @param file
      # @param tmp_dir
      #
      # @return When tmp_dir is set file URI otherwise file body.
      #
      def get_from_temporary_uploads(file:, tmp_dir:, alt_path: nil, hostname: nil, extension: 'dl')

        if hostname.nil?
          upl_int_tmp_uri = URI.parse(config[:urls][:upload_internal_tmp])
        else
          upl_int_tmp_uri = URI.parse(config[:cluster][:'file-servers'][hostname.to_sym])
        end

        if alt_path.nil?
          path = upl_int_tmp_uri.path[1..-1]
        else
          path = alt_path
        end

        org_file_url = "#{upl_int_tmp_uri.scheme}://#{upl_int_tmp_uri.host}:#{upl_int_tmp_uri.port}/#{path}/#{file}"
        tmp_file_uri = get_unique_file(tmp_dir: tmp_dir, extension: extension)

        response = HttpClient.get_to_file(url: org_file_url, to: tmp_file_uri)

        if 200 != response[:code]
          raise "#{response[:code]}"
        end

        # if temporary dir was provided
        if nil != tmp_dir
          # return file URI
          return tmp_file_uri
        end

        # read from file
        data = nil
        File.open(tmp_file_uri, 'rb') {
            | f | data = f.read
        }

        # return it's content
        return data
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

        if !company_id.nil? && user_id.nil?
          entity = ::SP::Job::BrokerArchiveClient::Entity.new(id: company_id.to_i, type: :company)
        elsif company_id.nil? && !user_id.nil?
          entity = ::SP::Job::BrokerArchiveClient::Entity.new(id: user_id.to_i, type: :user)
        else
          raise 'missing argument user_id/company_id' if user_id.nil? && company_id.nil?
        end

        # returning 'normalized' response
        broker_archive_client.reset(
          owner: thread_data.job_tube,
          job: {},
          headers: {
            'X-CASPER-BILLING-TYPE' => billing_type.to_s,
            'X-CASPER-BILLING-ID' => billing_id.to_s
          }
        ).create(
          entity: entity,
          billing: ::SP::Job::BrokerArchiveClient::Billing.new(id: billing_id, type: billing_type),
          permissions: access.to_s,
          uri: src_file,
          content_type: content_type.to_s,
          filename: file_name
        )
      end

      #
      # Archive a file from uploads/tmp to a permanent location in the file server
      #
      # @param tmp_file
      # @param final_file
      # @param content_type
      # @param access
      # @param user_id
      # @param company_id
      #
      def archive_on_file_server(tmp_file:, final_file: '', content_type:, access:, billing_type:, billing_id:, user_id: nil, company_id: nil)

        if !company_id.nil? && user_id.nil?
          entity = ::SP::Job::BrokerArchiveClient::Entity.new(id: company_id.to_i, type: :company)
        elsif company_id.nil? && !user_id.nil?
          entity = ::SP::Job::BrokerArchiveClient::Entity.new(id: user_id.to_i, type: :user)
        else
          raise 'missing argument user_id/company_id' if user_id.nil? && company_id.nil?
        end

        final_file = final_file.gsub(/&|\?/,'_')

        # returning 'normalized' response
        broker_archive_client.reset(
          owner: thread_data.job_tube,
          job: {},
          headers: {
            'X-CASPER-BILLING-TYPE' => billing_type.to_s,
            'X-CASPER-BILLING-ID' => billing_id.to_s
          }
        ).move(
          entity: entity,
          billing: ::SP::Job::BrokerArchiveClient::Billing.new(id: billing_id, type: billing_type),
          permissions: access.to_s,
          uri: tmp_file.to_s,
          content_type: content_type.to_s,
          filename: final_file
        )

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

        # returning 'normalized' response
        broker_archive_client.reset(
          owner: thread_data.job_tube,
          job: {
            entity_id: entity_id.to_s,
            user_id: user_id.to_s,
            role_mask: role_mask.to_s,
            module_mask: module_mask.to_s
          },
          headers: {
            'X-CASPER-BILLING-TYPE' => billing_type.to_s,
            'X-CASPER-BILLING-ID' => billing_id.to_s
          }
        ).delete(id: file_identifier)

      end

      #
      # Get a file from file server
      #
      # @param file_identifier
      # @param user_id
      # @param entity_id
      # @param role_mask
      # @param module_mask
      #
      # NOTE: Only works with files that are not binary
      def get_from_file_server (file_identifier:, user_id:, entity_id:, role_mask:, module_mask:, to_file: false, destination: nil)

        raise 'missing file_identifier' if file_identifier.nil?

        # returning 'normalized' response
        broker_archive_client.reset(
          owner: thread_data.job_tube,
          job: {
            entity_id: entity_id.to_s,
            user_id: user_id.to_s,
            role_mask: role_mask.to_s,
            module_mask: module_mask.to_s
          }
        )
        if to_file
          broker_archive_client.get_to_file(id: file_identifier, uri: destination)
        else
          broker_archive_client.get(id: file_identifier)
        end
      end

      #
      # Get a file from cdn
      #
      # @param cdn_url
      #
      # NOTE: Only works with files that are not binary
      def get_from_cdn (cdn_url:)

        raise 'missing cdn_url' if cdn_url.nil?

        # returning 'normalized' response
        HttpClient.get_klass.get( url: cdn_url )
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
        $redis.pipelined do |pipeline|
          pipeline.hset(redis_key, 'status', '{"status":"queued"}')
          pipeline.expire(redis_key, validity)
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
        if self.respond_to?(:tube_options)
          td.tube_options = default_tube_options.merge(self.tube_options)
        else
          td.tube_options = default_tube_options
        end
        if td.tube_options[:simpleapi]
          td.tube_options[:transient] = true
        end

        td.report_time_stamp      = 0
        td.exception_reported     = false
        td.job_id                 = job[:id]
        td.publish_key            = $config[:service_id] + ':' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        td.job_key                = $config[:service_id] + ':jobs:' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
        td.job_tube               = (job[:tube] || $args[:program_name])
        td.platform_configuration = nil
        td.color_scheme           = nil
        td.job_data               = {}

        # Make sure the job is still allowed to run by checking if the key exists in redis
        exists = redis do |r|
          if r.respond_to? 'exists?'
            r.exists?(td.job_key)
          else
            r.exists(td.job_key)
          end
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
            next if [:step, :progress, :message, :title, :status, :barrier, :index, :response, :action, :content_type, :status_code, :link, :custom, :simple_message].include? key
            message_args[key] = value
          end
          message = [ args[:message], message_args ]
          title = [ args[:title], message_args ] if args[:title]
        else
          message = nil
          title   = nil
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
        td.job_status[:custom]      = args[:custom] if args[:custom]

        if args.has_key? :response
          td.job_status[:response]     = args[:response]
          td.job_status[:content_type] = args[:content_type]
          td.job_status[:action]       = args[:action]
        end

        # Create notification that will be published
        td.job_notification = {}
        td.job_notification[:progress]    = progress.to_f.round(2) unless progress.nil?
        td.job_notification[:title]       = title unless title.nil?
        td.job_notification[:message]     = message unless message.nil?
        td.job_notification[:index]       = p_index unless p_index.nil?
        td.job_notification[:status]      = status.nil? ? 'in-progress' : status
        [:status_code, :custom, :link, :simple_message].each do |key|
          td.job_notification[key] = args[key] if args[key]
        end
        if args.has_key? :response
          td.job_notification[:response]     = args[:response]
          td.job_notification[:content_type] = args[:content_type]
          td.job_notification[:action]       = args[:action]
        end

        if ['completed', 'error', 'follow-up', 'cancelled'].include?(status) || (Time.now.to_f - td.report_time_stamp) > td.tube_options[:min_progress] || args[:barrier]
          update_progress_on_redis
          if td.current_job[:notification]
            notification_icon   = p_options && p_options[:icon] || td.current_job[:notification_options] && td.current_job[:notification_options][:icon] ||  "toc-icons:notification_SIS"
            notification_link   = p_options && p_options[:link] || td.current_job[:notification_options] && td.current_job[:notification_options][:link] ||  ""
            notification_remote = p_options && p_options[:remote] || td.current_job[:notification_options] && td.current_job[:notification_options][:remote] || false
            notification_title  = notification_title || p_options && p_options[:title] || td.current_job[:notification_options] && td.current_job[:notification_options][:title] || td.current_job[:notification_title] ||  "Notification title"

            if td.job_notification[:custom] && td.job_notification[:simple_message]
              td.job_notification[:message] = td.job_notification[:simple_message]
            end

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

            # Added role_mask and module_mask to notification message
            # Clearing notifications for employees
            message.merge!({ role_mask: td.current_job[:role_mask].to_i & ~1 }) if td.current_job[:role_mask]
            message.merge!({ module_mask: td.current_job[:module_mask] }) if td.current_job[:module_mask]

            manage_notification(notification_options, message)
          end
        end
      end

      def send_response (args)
        _send_response(args)
      end

      def _send_response (args)
        td = thread_data
        args[:status]       ||= 'completed'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:response]     ||= {}
        args[:status_code]  ||= 200

        is_raw_response = td.tube_options[:simpleapi] || td.tube_options[:raw_response]
        if is_raw_response
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

      def disconnect_db_connections
        td = thread_data

        if !$cdb.nil?
          # logger.debug "disconnect_if_has_post_connect_queries central db"
          $cdb.disconnect_if_has_post_connect_queries
        end
        if !$cluster_members.nil?
          $cluster_members.each do | number, member |
            if !member.db.nil?
              # logger.debug "disconnect_if_has_post_connect_queries cluster member #{number}"
              member.db.disconnect_if_has_post_connect_queries
            end
          end
        end

        if td.tube_options[:disconnect_db] == true
          if !$cdb.nil?
            # logger.debug "disconnect central db"
            $cdb.disconnect
          end
          if !$cluster_members.nil?
            $cluster_members.each do | number, member |
              if !member.db.nil?
                # logger.debug "disconnect cluster member #{number}"
                member.db.disconnect
              end
            end
          end
        end
      end

      def on_failure_for_all_jobs (e, *args)
        job = thread_data.current_job
        begin
          release_locks
          if job[:notification]
            if (e.is_a?(::SP::Job::JobAborted))
              _message = eval(e.message)[:args][:message]
            else
              _message = self.pg_server_error(e)
            end

            update_progress({
                status:  'error',
                action: 'response',
                content_type: 'application/json',
                status_code:  500,
                message: _message,
                progress: 100,
                detail: "Error in job with params: #{job} -> #{e}"
            })
          end
        rescue => e
          logger.error "**** FAILURE ALL JOBS **** #{e}"
        ensure
          disconnect_db_connections
        end
      end

      def after_perform_lock_cleanup (*args)
        disconnect_db_connections
        release_locks
        # In case the job missed a send_response... clear the job_id to mark this job as completed! (Otherwise, process reloading will NOT work)
        thread_data.job_id = nil
        check_gracefull_exit(dolog: true)
      end

      def check_gracefull_exit (dolog: false)
        if $gracefull_exit
          jobs = 0
          $thread_data.each do |thread, thread_data|
            unless thread_data.job_id.nil?
              jobs += 1
              begin
                if dolog
                  logger.info 'THIS JOB WAS NOT CLEARED - THREAD DATA INFO:'
                  logger.info thread_data.to_json
                else
                  puts 'THIS JOB WAS NOT CLEARED - THREAD DATA INFO:'
                  puts thread_data.to_json
                end
              rescue => e
                logger.info e
              end
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
        td = thread_data
        if td.tube_options[:broker] == true
          raise "Implementation error : please use 'raise' instead of report_error or raise_error"
        end
        args[:status]       ||= 'error'
        args[:action]       ||= 'response'
        args[:content_type] ||= 'application/json'
        args[:status_code]  ||= 500
        logger.error(args)
        if td.tube_options[:simpleapi]
          args[:response] ||= { error: args[:message] }
          _send_response(args)
        else
          update_progress(args)
          signal_job_termination(td)
          td.job_id = nil
        end
        td.exception_reported = true
      end

      #
      # @NOTE: do not use this method if td.tube_options[:broker] == true
      #
      def report_error (args)
        td = thread_data
        error_handler(args)
        raise ::SP::Job::JobAborted.new(args: args, job: td.current_job)
      end

      #
      # @NOTE: do not use this method if td.tube_options[:broker] == true
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
          if td.tube_options[:transient] == true
            $redis.publish td.publish_key, td.job_notification.to_json
          else
            $redis.pipelined do |pipeline|
              pipeline.publish td.publish_key, td.job_notification.to_json
              pipeline.hset    td.job_key, 'status', td.job_status.to_json
            end
          end
        else
          $redis_mutex.synchronize {
            if td.tube_options[:transient] == true
              $redis.publish td.publish_key, td.job_notification.to_json
            else
              $redis.pipelined do |pipeline|
                pipeline.publish td.publish_key, td.job_notification.to_json
                pipeline.hset    td.job_key, 'status', td.job_status.to_json
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

      def search_on_member (redis_client, redis_key, pattern)
        cursor = 0
        grab_result = []
        loop do
          notification_exists = scan_on_member(redis_client, redis_key, cursor, pattern)
          break if notification_exists.nil?
          cursor = notification_exists.first
          grab_result << notification_exists[1]

          if notification_exists.first == '0'
            find_result = grab_result.flatten.compact.first
            logger_or_puts({action: 'found search on member', pattern: pattern}.to_json) if find_result
            return find_result if find_result
            break
          end
        end

      end

      def clean_notifications (redis_client, redis_key, pattern)
        cursor = 0
        loop do
          notification_exists = scan_on_member(redis_client, redis_key, cursor, pattern)
          break if notification_exists.nil?

          cursor = notification_exists.first

          if notification_exists[1] && notification_exists[1].any?
            notification_exists[1].map do |key|
              redis_client.srem(redis_key[:key], "#{key}")
              redis_client.publish(redis_key[:public_key], "#{{ id: JSON.parse(key)["id"], destroy: true }.to_json}")
            end
          end

          break if notification_exists.first == '0'
        end
      end

      def scan_on_member (redis_client, redis_key, cursor, pattern)
        redis_client.sscan(redis_key[:key], cursor, { match: pattern, count: 100 })
      end

      def publish_notification(publish_object, options = {})

        options = {
          service: config[:service_id],
          type: 'notifications'
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

        redis_client.publish redis_key[:public_key], "#{publish_object.to_json}"

      end

      def manage_notification(options = {}, notification = {})
        options = {
          service: config[:service_id],
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

          unless notification.key?(:resource_job_queue_name)
            clean_notifications(redis_client, redis_key, "*\"tube\":\"#{job_type}*\"*")
          else
            clean_notifications(redis_client, redis_key, "*\"icon\":\"#{notification[:icon]}\"*\"resource_job_queue_name\":\"#{notification[:resource_job_queue_name]}*")
          end

          redis_client.sadd redis_key[:key], "#{notification.to_json}"
          logger_or_puts({ action: options[:action], key: redis_key[:key], object: notification }.to_json)

          redis_client.publish redis_key[:public_key], "#{response_object.to_json}"

        elsif options[:action] == :update
          find_search_on_member = search_on_member(redis_client, redis_key, "*id\":\"#{notification[:id]}\"*")

          if find_search_on_member
            notification.merge!({id: notification[:id]}) if notification[:id]
            response_object = notification

            redis_client.srem redis_key[:key], "#{find_search_on_member}"
            notification.delete(:identity)

            redis_client.sadd redis_key[:key], "#{notification.to_json}"
            logger_or_puts({ action: options[:action], key: redis_key[:key], object: notification }.to_json)

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

          find_search_on_member = search_on_member(redis_client, redis_key, "*id\":\"#{notification[:identity]}\"*")

          if find_search_on_member
            response_object = { id: notification[:identity], destroy: true } if notification[:identity]
            rem_response = redis_client.srem redis_key[:key], find_search_on_member
            logger_or_puts({ action: 'delete', key: redis_key[:key], identity: notification[:identity], object: find_search_on_member, rem_response: rem_response }.to_json)
            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
          else
            response_object = { id: notification[:identity], destroy: true } if notification[:identity]
            redis_client.publish redis_key[:public_key], "#{response_object.to_json}"
            logger_or_puts({not_found_in_member: true, action: 'delete', notification: notification}.to_json)
          end

        end

      end

      def email_address_valid? (email)
        return false if email.match(RFC822::EMAIL).nil?
        begin
          resolver = Dnsruby::DNS.new
          domain = Mail::Address.new(email).domain

          resolver.each_resource(domain, 'MX') do |r|
            return true
          end
          resolver.each_resource(domain, 'A') do |r|
            return true
          end
          return false
        rescue ::Exception => e
          return false
        end
      end

      def email_addresses_valid? (email_addresses)
        begin
          raise ::ArgumentError.new 'A lista de emails tem de estar preenchida' if email_addresses.nil? || email_addresses.empty?

          email_addresses = email_addresses.split(',').map(&:strip)
          valid_email_addresses = email_addresses.select { |email| !email.match(RFC822::EMAIL).nil? }
          diff_email_addresses = email_addresses - valid_email_addresses

          raise ::Exception.new "Os seguintes endereços de email não são válidos: #{diff_email_addresses.join(', ')}" if diff_email_addresses.length > 0

          resolver = Dnsruby::DNS.new

          mx_not_found = []

          valid_email_addresses.each do |email|
            begin
              domain = Mail::Address.new(email).domain
              has_resource = false
              resolver.each_resource(domain, 'MX') do |r|
                has_resource = true
                break;
              end
              unless has_resource
                resolver.each_resource(domain, 'A') do |r|
                  has_resource = true
                  break;
                end
              end
              mx_not_found << email if !has_resource
            rescue Exception => e
              mx_not_found << email
            end
          end

          raise ::Exception.new "Os seguintes endereços de email não são válidos: #{mx_not_found.join(', ')}" if mx_not_found.length > 0

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

      def archive_email (email_html, entity_id)
        access = "drw = entity_id == #{entity_id} && (role_mask & #{get_role_mask(['manager','accountant','company_accountant','payroller','transaction_accountant'])});"

        tmp_file = SP::Job::Unique::File.create("/tmp/#{(Date.today + 2).to_s}", ".html")
        File.open(tmp_file, 'wb') { |f| f.write(email_html) }

        response = self.send_to_file_server(file_name: "#{entity_id}_email.html",
                                            src_file: tmp_file,
                                            content_type: 'text/html',
                                            access: access,
                                            billing_type: 'email',
                                            billing_id: entity_id.to_i,
                                            company_id: entity_id.to_i)
        return response[:id]
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
              ___internal: ___internal,
              attachments: args[:attachments]
            }
          )
      end

      def synchronous_send_email (args)

        if args.has_key?(:body) && args[:body] != nil
          email_body = args[:body]
        elsif args.has_key?(:template) && args[:template] != nil
          email_body = expand_mail_body args[:template]
        elsif args.has_key?(:email_id) && args[:email_id] != nil
          email_body = get_from_file_server(file_identifier: args[:email_id],
                                            user_id: args[:session][:user_id],
                                            entity_id: args[:session][:entity_id],
                                            role_mask: args[:session][:role_mask],
                                            module_mask: args[:session][:module_mask])
        elsif args.has_key?(:cdn_url) && args[:cdn_url] != nil
          email_body = get_from_cdn(cdn_url: args[:cdn_url])[:body]
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
          from     args[:default_from]
          to       to_email
          cc       cc_email unless cc_email.nil?
          subject  args[:subject]
          reply_to (args[:reply_to] || args[:default_from])

          html_part do
            content_type 'text/html; charset=UTF-8'
            body email_body
          end
        end

        if args.has_key?(:attachments) && args[:attachments] != nil
          args[:attachments].each do |attach|
            uri = "#{attach[:protocol]}://#{attach[:host]}:#{attach[:port]}/#{attach[:path]}"
            if attach.has_key?(:id) # archived file?
              # from FSOPO ( file by id )
              uri += "/#{attach[:id]}"
            else  # temporary cluster file
              # file by name
              uri += "/#{attach[:file]}" if attach.has_key?(:file) && !attach[:file].nil?
            end
            if false == args[:session].nil? && false == args[:session][:role_mask].nil?
              attach_http_call = Curl::Easy.http_get(URI.escape(uri)) do |http|
                http.headers['X-CASPER-USER-ID'] = args[:session][:user_id]
                http.headers['X-CASPER-ENTITY-ID'] = args[:session][:entity_id]
                http.headers['X-CASPER-ROLE-MASK'] = args[:session][:role_mask]
                http.headers['X-CASPER-MODULE-MASK'] = args[:session][:module_mask]
                http.headers['User-Agent'] = "curb/mail-queue"
              end
            else
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
        while base_exception.respond_to?(:cause) && !base_exception.cause.to_s.strip.empty?
          base_exception = base_exception.cause
        end

        return base_exception.is_a?(PG::ServerError) ? base_exception.result.error_field(PG::PG_DIAG_MESSAGE_PRIMARY) : e.message
      end

      def file_to_downloadable_url (path, expiration = nil)
        if OS.mac?
          file = File.join(path.split('/')[3..-1])
        else
          file = File.join(path.split('/')[2..-1])
        end

        now = Time.now.getutc.to_i
        exp = expiration.nil? ? now + (3600 * 24 * 7) : now + expiration

        download_uri = URI.parse(config[:urls][:download_internal])
        private_key = config[:certificates][:broker][:private]
        jwt = ::SP::Job::JWTHelper.encode(
          key: private_key,
          payload: {
            exp: exp,
            iat: now,
            nbf: now,
            action: 'redirect',
            redirect: {
              protocol: download_uri.scheme,
              host: download_uri.host,
              port: download_uri.port,
              path: download_uri.path[1..-1],
              file: file
            }
          }
        )

        cluster_url = URI.parse(app_url(brand: thread_data.current_job[:brand]))
        cluster_url.path = "/downloads/#{jwt}"
        cluster_url.to_s
      end

      def file_identifier_to_url (id, filename)
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

      #
      # Prints massive payloads without causing beanstalk issues
      # Uses cpq-deflator (zip) or cpq-amalgamator (download or print)
      #
      # @param casper-print-queue payload
      # @param action zip / download / print
      # @return cpq-deflator/cpq-amalgamator job id
      #
      def massive_print (payload:, action: 'download')
        tempfile = File.open(get_unique_file(extension: '.json'), 'wb')
        tempfile.write payload.to_json
        tempfile.flush
        tempfile.close

        payload = {
          job: {
            url: get_cdn_internal_for(tempfile.path),
            ttr: 360,
            validity: 100
          },
          validity: 100
        }

        if action == 'zip'
          payload[:tube] = 'cpq-deflator'
        elsif action == 'download' || action == 'print'
          payload[:tube] = 'cpq-amalgamator'
        else
          report_error(message: 'Invalid action')
        end

        return submit_job payload
      end

      #
      # Print and archive (via sequencer)
      #
      # Prints the requested PDF and archives it on the entity file server with the set access permissions,
      # the size of the archived file is added to the specified billing category
      #
      # @param payload the print payload for casper-print-queue
      # @param entity_id the entity that will own the archived file
      # @param access the archived file permission rights
      # @param file_name external name of the file as seen by the user / front-end
      # @param billing_type the billing category that will be "charged" with archived file
      #
      # @return symbolized file server response, namely:
      #    id: i.e. the internal file identifier in the file server
      #    'content-type': the content type, application/pdf,
      #    'content-length': size in bytes of the archived PDF
      #    name: human name of the file
      #
      def print_and_archive (payload:, entity_id:, access:, file_name: '', billing_type:)
        #
        # set payloads
        #
        begin
          # patch print payload
          print_payload = payload
          print_payload[:tube]           ||= 'casper-print-queue'
          print_payload[:ttr]            ||= 300
          print_payload[:validity]       ||= 500
          print_payload[:auto_printable] ||= false
          print_payload[:documents]      ||= []
          # set archive payload
          archive_payload = {
            ttr: 120,
            validity: 240,
            tube: 'pdf-archivist',
            payload: {
              billing: {
                id: entity_id,
                type: billing_type
              },
              access: access,
              entity_id: entity_id,
              uri: "$.responses[0].redirect.protocol + '://' + $.responses[0].redirect.host + ':' + $.responses[0].redirect.port + '/' + $.responses[0].redirect.file"
            },
          }
          if nil != file_name && file_name.length > 0
            archive_payload[:payload].merge!({name: file_name})
          end
          # set sequencer payload
          sequencer_payload = {
              tube: 'sequencer-live',
              ttr: ( print_payload[:ttr] + archive_payload[:ttr] ),
              validity: ( print_payload[:validity] + archive_payload[:validity] ),
              jobs: [
                {
                  tube: print_payload[:tube],
                  ttr: print_payload[:ttr],
                  validity: print_payload[:validity],
                  payload: print_payload
                },
                archive_payload
              ]
          }
        rescue => e
          rollbar_and_raise(message: 'An error occurred while creating P&A sequence payload', owner: 'print_and_archive', tube: thread_data.job_tube, exception: e)
        end
        logger.debug "SEQUENCER PAYLOAD:"
        logger.debug ap sequencer_payload

        synchronous_job(sequencer_payload)
      end

      def synchronous_job(sequencer_payload, expect = { code: 200 }, owner = 'synchronous_job')

        #
        # "submit job" via jobify module to sequencer-live tube - synchronous HTTP request
        #
        # set JWT

        # perform HTTP request
        begin
          response = HttpClient.post(
            url: "#{config[:urls][:internal_jobify]}/sequencer-live",
            headers: {
              'Content-Type' => 'application/json'
            },
            body: sequencer_payload.to_json,
            expect: expect,
            conn_options: {
              connection_timeout: sequencer_payload[:ttr],
              request_timeout: sequencer_payload[:ttr]
            }
          )
        rescue EasyHttpClient::Error => he
          logger.error "#{ap he.detail}".red
          logger.error ap he.response
          rollbar_and_raise(message: 'An error occurred while performing an operation', owner: owner, tube: thread_data.job_tube, exception: he)
        rescue => e
          logger.info "RAISE GENERIC: #{ap e}".red
          rollbar_and_raise(message: 'An error occurred while performing an operation', owner: owner, tube: thread_data.job_tube, exception: e)
        end
        # done - log
        logger.debug "RESPONSE:"
        logger.debug ap response
        # done - on success, archive response is expected
        JSON.parse(response[:body], symbolize_names: true)
      end

      def save_json_document (entity_id:, sharded_schema:, type:, key:, document: nil, data: nil)
        j_document = document
        j_data     = data

        fields = ['id', 'type', 'company_id']
        fields << 'document' unless document.nil?
        fields << 'data'     unless data.nil?

        if !document.nil? && document.is_a?(Hash)
          j_document = document.to_json
        end

        if !data.nil? && data.is_a?(Hash)
          j_data = data.to_json
        end

        values = [key, type, entity_id]
        values << j_document unless document.nil?
        values << j_data     unless data.nil?

        rs = db.execp(%Q[
          INSERT INTO #{sharded_schema}.json_documents (#{fields.join(', ')})
          VALUES (#{fields.each_with_index.map { |_, i| "$#{i + 1}" }.join(', ')})
          ON CONFLICT(id, type, company_id)
          DO UPDATE SET #{fields.each_with_index.map { |field, i| "#{field} = $#{i + 1}" }.join(', ')}
          RETURNING id, type, company_id
        ], *values)

        if 'PGRES_TUPLES_OK' == rs.res_status(rs.result_status)
          return {
            id:        key,
            type:      type,
            entity_id: entity_id
          }
        end

        return false
      end

      private

      def logger_or_puts msg
        # OUTPUT FOR JOBS OR RUBY CONSOLE
        if logger
          logger.info " => #{msg}".yellow
        else
          puts " => #{msg}".yellow
        end

      end

      def get_random_folder
        ALPHABET[rand(26)] + ALPHABET[rand(26)]
      end

    end # Module Common
  end # Module Job
end # Module SP
