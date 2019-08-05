#!/usr/bin/env ruby
#
# encoding: utf-8
#
# Copyright (c) 2017 Cloudware S.A. Allrights reserved
#
# Helper to obtain tokens to access toconline API's.
#

require 'sp/job/jsonapi_error'

module SP
  module Job

    class Broker

      #
      # Helper class that defined an 'i18n' message.
      #
      class I18N

        attr_accessor :key
        attr_accessor :args

        def initialize (key:, args:)
          @key = key
          @args = args
        end

      end


      #
      # Helper class that defined an 'Broker' error.
      #
      class Error < ::SP::Job::JSONAPI::Error

        def initialize (i18n:, code:, internal:)
          super(status: code, code: code, detail: nil, internal: internal)
          @i18n = i18n
        end

      end

      #
      # Helper class that defined an 'Not Implemented' error.
      #
      class NotImplementedError < Error

        def initialize (i18n:, internal:)
          super(i18n: i18n, code: 501, internal: internal)
        end

      end

      #
      # Helper class that defined an 'Not Found' error.
      #
      class NotFound < Error

        def initialize (i18n:, internal:)
          super(i18n: i18n, code: 404, internal: internal)
        end

      end

      #
      # Helper class that defined an 'Bard Request' error.
      #
      class BadRequest < Error

        def initialize (i18n:, internal:)
          super(i18n: i18n, code: 400, internal: internal)
        end

      end

      #
      # Helper class that defined an 'Internal Error' error.
      #
      class InternalError < Error

        def initialize (i18n:, internal:)
          super(i18n: i18n, code: 500, internal: internal)
        end

      end

      #
      # Helper class that defined an 'Unauthorized' error.
      #
      class Unauthorized < Error

        def initialize (i18n:, internal:)
          super(i18n: i18n, code: 401, internal: internal)
        end

      end

      #
      #
      #
      class OAuth2

        def initialize (service_id:, config:, redis: nil)
          @service_id = service_id
          @client = ::SP::Job::BrokerOAuth2Client.new(
            protocol:      config[:protocol],
            host:          config[:host],
            port:          config[:port],
            client_id:     config[:client_id],
            client_secret: config[:client_secret],
            redirect_uri:  config[:redirect_uri],
            scope:         config[:scope],
            options:       {}
          )
          @redis = redis
        end

        #
        # Obtain an 'access' and a 'refresh' token.
        #
        # @param scope
        #
        def authorize (scope: nil, fields: nil)
          # obtain an 'authorization code'
          ac_response = @client.get_authorization_code(
            a_redirect_uri = nil,
            a_scope = scope
          )
          # got a valid 'authorization code'?
          if ac_response[:oauth2].has_key?(:code)
            # got fields?
            if nil != fields
              # prepare redis arguments: field value, [field value, ...]
              array = []
              fields.each do |k,v|
                array << k.to_s
                array << v
              end
              @redis.hmset("#{@service_id}:oauth:authorization_code:#{ac_response[:oauth2][:code]}",
                array,
                'patched_by', 'toconline-session'
              )
           end
            # exchange it for a 'access' and a 'refresh' token
            at_response = @client.exchange_auth_code_for_token(
              ac_response[:oauth2][:code]
            )
            # return 'oauth2' at object
            return at_response
          else
            # return 'oauth2' ac object
            return ac_response
          end
        end

        #
        # Refresh an access token.
        #
        # @param scope
        # @param old
        #
        def refresh(scope: nil, old: nil, delete: true)
          at_response = @client.refresh_access_token(
            a_refresh_token = old[:refresh_token],
            a_scope = scope
          )
          if true == at_response[:oauth2].has_key?(:error)
            return at_response
          end
          # no error, delete old tokens
          if nil == old
            # return oauth response
            return at_response
          end
          # old tokens provided: remove them from redis
          if nil == @redis || nil == @service_id
            raise InternalError.new(i18n: nil, internal: nil)
          end
          # delete old tokens from redis
          if true == delete
            @redis.multi do |multi|
              if nil != old[:access_token]
                multi.del("#{@service_id}:oauth:access_token:#{old[:access_token]}")
              end
              if nil != old[:refresh_token]
                multi.del("#{@service_id}:oauth:refresh_token:#{old[:refresh_token]}")
              end
            end
          end
          # return oauth response
          return at_response
        end

        #
        # Patch a pair of tokens, by generating new ones
        #
        # @param access_token
        # @param refresh_token
        # @param fields
        #
        def patch (access_token:, refresh_token:, fields:)
          if nil == @redis || nil == @service_id
            raise InternalError.new(i18n: nil, internal: nil)
          end
          # generate new pair, based on provided refresh_token
          at_response = @client.refresh_access_token(
            a_refresh_token = refresh_token,
            a_scope = nil # keep current scope
          )
          if at_response[:oauth2].has_key?(:error)
            raise ::SP::Job::Broker::InternalError.new(i18n: nil, internal: at_response[:oauth2][:error])
          end
          # prepare redis arguments: field value, [field value, ...]
          array = []
          fields.each do |k,v|
            array << k.to_s
            array << v
          end
          # patch new tokens
          @redis.multi do |multi|
            multi.hmset("#{@service_id}:oauth:refresh_token:#{at_response[:oauth2][:refresh_token]}",
               array,
              'patched_by', 'toconline-session'
            )
            multi.hmset("#{@service_id}:oauth:access_token:#{at_response[:oauth2][:access_token]}",
               array,
              'patched_by', 'toconline-session'
            )
          end
          # delete old tokens from redis
          @redis.multi do |multi|
            multi.del("#{@service_id}:oauth:access_token:#{access_token}")
            multi.del("#{@service_id}:oauth:refresh_token:#{refresh_token}")
          end
          # return oauth response
          return at_response
        end

        #
        # Remove a pair of tokens from redis.
        #
        # @param access
        # @param refresh
        #
        def dispose (access:, refresh:)
          if nil == @redis || nil == @service_id
            raise InternalError.new(i18n: nil, internal: nil)
          end

          if refresh.nil?
            refresh = @redis.hget("#{@service_id}:oauth:access_token:#{access}",'refresh_token')
          end

          # delete tokens from redis
          @redis.multi do |multi|
            multi.del("#{@service_id}:oauth:access_token:#{access}")
            multi.del("#{@service_id}:oauth:refresh_token:#{refresh}")
          end
          #
          nil
        end

      end

      #
      #
      #
      class Job

        #
        #
        #
        attr_accessor :oauth2
        attr_accessor :output

        #
        #
        #
        def initialize (config:)
          if nil != config && nil != config[:oauth2]
            @oauth2 = OAuth2.new(service_id: config[:service_id], config: config[:oauth2], redis: config[:redis])
          else
            @oauth2 = nil
          end
          @output = {
            :action       => "response",
            :content_type => "application/json",
            :status_code  => 400,
            :response     => nil
          }
        end

        #
        # Obtain an 'access' and a 'refresh' token.
        #
        # @param args check the authorize method o OAuth2 class
        # @return hash with response content type and status code
        #
        def authorize (args)
          call do
            finalized(response: oauth2.authorize(args))
          end
          @output
        end

        #
        # Refresh an access token.
        #
        # @param args check the refresh method o OAuth2 class
        # @return hash with response content type and status code
        #
        def refresh (args)
          call do
            finalized(response: oauth2.refresh(args))
          end
          @output
        end

        #
        # Patch a pair of tokens, by generating new ones
        #
        # @param args check the patch methods o OAuth2 class
        # @return hash with response content type and status code
        #
        def patch (args)
          call do
            finalized(response: oauth2.patch(args))
          end
          @output
        end

        #
        # Remove a pair of tokens from redis.
        #
        # @param args check the dispose method o OAuth2 class
        # @return hash with response content type and status code
        #
        def dispose (args)
          call do
            finalized(response: oauth2.dispose(args))
          end
          @output
        end

        #
        # Finalize the job response.
        #
        # @param response
        # @param content_type
        # @param status_code
        #
        # @return hash with response content type and status code
        #
        def finalized (response:, content_type: 'application/json', status_code: 200)
          @output[:response]     = response
          @output[:content_type] = content_type
          @output[:status_code]  = status_code
          @output
        end

        #
        # Perform an OAuth2 request, catch errors
        # and convert them to a common result hash.
        #
        # @param callback
        #
        def call(*callback)
          @output = {}
          begin
            @output = yield
          rescue ::SP::Job::BrokerOAuth2Client::InvalidEmailOrPassword => invalid_password
            @output[:status_code] = 403
            @output[:content_type], @output[:response] = Error.new(i18n: nil, code: @output[:status_code],
              internal: invalid_password.as_hash[:oauth2]
            ).content_type_and_body()
          rescue ::SP::Job::BrokerOAuth2Client::AccessDenied => acccess_denied
            @output[:status_code] = 403
            @output[:content_type], @output[:response] = Error.new(i18n: nil, code: @output[:status_code],
              internal: acccess_denied.as_hash[:oauth2]
            ).content_type_and_body()
          rescue ::SP::Job::BrokerOAuth2Client::UnauthorizedUser => unauthorized_user
            @output[:status_code] = 401
            @output[:content_type], @output[:response] = Error.new(i18n: nil, code: @output[:status_code],
              internal: unauthorized_user.as_hash[:oauth2]
            ).content_type_and_body()
          rescue ::SP::Job::BrokerOAuth2Client::InternalError => internal_error
            @output[:status_code] = 500
            @output[:content_type], @output[:response] = Error.new(i18n: nil, code: @output[:status_code],
              internal: internal_error.as_hash[:oauth2]
            ).content_type_and_body()
          rescue ::SP::Job::BrokerOAuth2Client::Error => error
            @output[:status_code] = 500
            @output[:content_type], @output[:response] = Error.new(i18n: nil, code: @output[:status_code],
              internal: error.as_hash[:oauth2]
            ).content_type_and_body()
          rescue NotImplementedError => broker_not_implemented
            @output[:status_code] = broker_not_implemented.code
            @output[:content_type], @output[:response] = b_not_implemented.content_type_and_body()
          rescue BadRequest => broker_bad_request
            @output[:status_code] = broker_bad_request.code
            @output[:content_type], @output[:response] = broker_bad_request.content_type_and_body()
          rescue InternalError => broker_internal_error
            @output[:status_code] = broker_internal_error.code
            @output[:content_type], @output[:response] = broker_internal_error.content_type_and_body()
          rescue Error => broker_error
            @output[:status_code] = broker_error.code
            @output[:content_type], @output[:response] = broker_error.content_type_and_body()
          rescue Exception => e
            internal_error = InternalError.new(i18n: nil, internal: e.message)
            @output[:status_code] = internal_error.code
            @output[:content_type], @output[:response] = internal_error.content_type_and_body()
          end
          @output
        end

      end

    end # end class 'Job'

  end # module Job
end# module SP
