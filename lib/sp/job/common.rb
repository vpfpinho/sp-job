#
# And this is the mix-in we'll apply to Job execution class
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

      def before_perform_init (job)

        if $connected == false
          database_connect
          $redis.get "#{$config}:jobs:sequential_id"
          $connected = true
        end

        $job_status = {
          action:       'response',
          content_type: 'application/json',
          progress:      0
        }
        $report_time_stamp     = 0
        $job_status[:progress] = 0
        $exception_reported    = false
        $redis_key             = $config[:service_id] + ':' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
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
        $job_key = $config[:service_id] + ':jobs:' + (job[:tube] || $args[:program_name]) + ':' + job[:id]
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
        step     = args[:step]
        status   = args[:status]
        progress = args[:progress]
        barrier  = args[:barrier]
        p_index  = args[:index]
        response = args[:response]

        if args.has_key? :message
          message_args = Hash.new
          args.each do |key, value|
            next if [:step, :progress, :message, :status, :barrier, :index, :response].include? key
            message_args[key] = value
          end
          message = [ args[:message], message_args ]
        else
          message = nil
        end
        $job_status[:progress] = progress.to_f.round(2) unless progress.nil?
        $job_status[:progress] = ($job_status[:progress] + step.to_f).round(2) unless step.nil?
        $job_status[:message]  = message unless message.nil?
        $job_status[:index]    = p_index unless p_index.nil?
        $job_status[:status]   = status.nil? ? 'in-progress' : status
        $job_status[:response] = response unless response.nil?
        if args.has_key? :link
          $job_status[:link] = args[:link]
        end

        if args.has_key? :extra
          args[:extra].each do |key, value|
            $job_status[key] = value
          end
        end

        if status == 'completed' || status == 'error' || (Time.now.to_f - $report_time_stamp) > $min_progress || barrier
          update_progress_on_redis
        end
      end

      def raise_error (args)
        args[:status] = 'error'
        update_progress(args)
        $exception_reported = true
        raise args[:message]
      end

      def update_progress_on_redis
        $redis.pipelined do
          redis_str = $job_status.to_json
          $redis.publish $redis_key, redis_str
          $redis.hset    $redis_key, 'status', redis_str
          $redis.expire  $redis_key, $validity
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

      def db_exec (query)
        $pg.query(query: query)
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

      def send_email (args)
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

        begin
          m.deliver!
          # ap m.to_s
          return OpenStruct.new(status: true)
        rescue Net::OpenTimeout => e
          ap ["OpenTimeout", e]
          return OpenStruct.new(status: false, message: e.message)
        rescue Exception => e
          ap e
          return OpenStruct.new(status: false, message: e.message)
        end

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

      def catch_fatal_exceptions (e)
        case e
        when PG::UnableToSend, PG::AdminShutdown, PG::ConnectionBad
          logger.fatal "Lost connection to database exiting now"
          exit
        when Redis::CannotConnectError
          logger.fatal "Can't connect to redis exiting now"
          exit
        end
      end

    end # Module Common
  end # Module Job
end # Module SP