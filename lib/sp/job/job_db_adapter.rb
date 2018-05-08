module SP
  module Job

    unless RUBY_ENGINE == 'jruby'  # TODO suck in the base class from SP-DUH

      class JobDbAdapter < ::SP::Duh::JSONAPI::Adapters::Db

        private

          # Implement the JSONAPI request by direct querying of the JSONAPI function in the database
          def do_request_on_the_db(method, path, params)
            jsonapi_query = %Q[ SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, company_id, company_schema, sharded_schema, accounting_schema, accounting_prefix
            response.first if response.first
          end

          def explicit_do_request_on_the_db(exp_accounting_schema, exp_accounting_prefix, method, path, params)
            jsonapi_query = %Q[ SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, company_id, company_schema, sharded_schema, exp_accounting_schema, exp_accounting_prefix
            response.first if response.first
          end

          def user_id           ; service.parameters.user_id ; end
          def company_id        ; service.parameters.company_id ; end
          def company_schema    ; service.parameters.company_schema.nil? ? nil : service.parameters.company_schema ; end
          def sharded_schema    ; service.parameters.sharded_schema.nil? ? nil : service.parameters.sharded_schema ; end
          def accounting_schema ; service.parameters.accounting_schema.nil? ? nil : service.parameters.accounting_schema ; end
          def accounting_prefix ; service.parameters.accounting_prefix.nil? ? nil : service.parameters.accounting_prefix ; end

      end

    end

  end
end
