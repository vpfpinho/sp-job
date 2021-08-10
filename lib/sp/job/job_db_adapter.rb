module SP
  module Job

    unless Kernel.const_defined?("::SP::Duh")  # TODO suck in the base class from SP-DUH
      class JobDbAdapter < ::SP::JSONAPI::Adapters::Db

        private

          # Implement the JSONAPI request by direct querying of the JSONAPI function in the database
          def do_request_on_the_db(method, path, params)

            jsonapi_query = %Q[ SET statement_timeout = '60min'; SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'); ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, entity_id, entity_schema, sharded_schema, subentity_schema, subentity_prefix
            response.first if response.first
          end

          def explicit_do_request_on_the_db(exp_subentity_schema, exp_subentity_prefix, method, path, params)
            jsonapi_query = %Q[ SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, entity_id, entity_schema, sharded_schema, exp_subentity_schema, exp_subentity_prefix
            response.first if response.first
          end

          def user_id          ; service.parameters.user_id ; end
          def entity_id        ; service.parameters.entity_id ; end
          def entity_schema    ; service.parameters.entity_schema.nil? ? nil : service.parameters.entity_schema ; end
          def sharded_schema   ; service.parameters.sharded_schema.nil? ? nil : service.parameters.sharded_schema ; end
          def subentity_schema ; service.parameters.subentity_schema.nil? ? nil : service.parameters.subentity_schema ; end
          def subentity_prefix ; service.parameters.subentity_prefix.nil? ? nil : service.parameters.subentity_prefix ; end

      end

    else

      class JobDbAdapter < ::SP::Duh::JSONAPI::Adapters::Db

        private

          # Implement the JSONAPI request by direct querying of the JSONAPI function in the database
          def do_request_on_the_db(method, path, params)
            jsonapi_query = %Q[ SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, entity_id, entity_schema, sharded_schema, subentity_schema, subentity_prefix
            response.first if response.first
          end

          def explicit_do_request_on_the_db(exp_subentity_schema, exp_subentity_prefix, method, path, params)
            jsonapi_query = %Q[ SELECT * FROM public.jsonapi('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s') ]

            response = service.connection.exec jsonapi_query, method, (method == 'GET' ? url_with_params_for_query(path, params) : url(path)), (method == 'GET' ? '' : params_for_body(params)), user_id, entity_id, entity_schema, sharded_schema, exp_subentity_schema, exp_subentity_prefix
            response.first if response.first
          end

          def user_id          ; service.parameters.user_id ; end
          def entity_id        ; service.parameters.entity_id ; end
          def entity_schema    ; service.parameters.entity_schema.nil? ? nil : service.parameters.entity_schema ; end
          def sharded_schema   ; service.parameters.sharded_schema.nil? ? nil : service.parameters.sharded_schema ; end
          def subentity_schema ; service.parameters.subentity_schema.nil? ? nil : service.parameters.subentity_schema ; end
          def subentity_prefix ; service.parameters.subentity_prefix.nil? ? nil : service.parameters.subentity_prefix ; end

      end

    end

  end
end
