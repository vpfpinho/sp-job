module SP
  module JSONAPI
    module Adapters

      class Base

        def service ; @service ; end

        def initialize(service)
          @service = service
        end

        def get(path, params = {})
          request('GET', path, params)
        end
        def post(path, params = {})
          request('POST', path, params)
        end
        def patch(path, params = {})
          request('PATCH', path, params)
        end
        def delete(path)
          request('DELETE', path, nil)
        end

        def get!(path, params = {})
          request!('GET', path, params)
        end
        def post!(path, params = {})
          request!('POST', path, params)
        end
        def patch!(path, params = {})
          request!('PATCH', path, params)
        end
        def delete!(path)
          request!('DELETE', path, nil)
        end

        def get_explicit!(exp_subentity_schema, exp_subentity_prefix, path, params = {})
          explicit_request!(exp_subentity_schema, exp_subentity_prefix, 'GET', path, params)
        end
        def post_explicit!(exp_subentity_schema, exp_subentity_prefix, path, params = {})
          explicit_request!(exp_subentity_schema, exp_subentity_prefix, 'POST', path, params)
        end
        def patch_explicit!(exp_subentity_schema, exp_subentity_prefix, path, params = {})
          explicit_request!(exp_subentity_schema, exp_subentity_prefix, 'PATCH', path, params)
        end
        def delete_explicit!(exp_subentity_schema, exp_subentity_prefix, path)
          explicit_request!(exp_subentity_schema, exp_subentity_prefix, 'DELETE', path, nil)
        end

        def get_specific_service!(path, params, service_params)
          specific_service_do_request!('GET', path, params, service_params)
        end

        alias_method :put, :patch
        alias_method :put!, :patch!
        alias_method :put_explicit!, :patch_explicit!

        def unwrap_request
          unwrap_response(yield)
        end

        # do_request MUST be implemented by each specialized adapter, and returns a tuple: the request status and a JSONAPI string or hash with the result
        def do_request(method, path, params) ; ; end
        def explicit_do_request(exp_subentity_schema, exp_subentity_prefix, method, path, params) ; ; end

        def request(method, path, params)
          # As it is now, this method is EXACTLY the same as request!()
          # And it cannot be reverted without affecting lots of changes already made in the app's controllers.
          # TODO: end it, or end the !() version
          # begin
            unwrap_request do
              do_request(method, path, params)
            end
          # THIS CAN'T BE DONE, because the same method cannot return both a single result (in case there is NOT an error) and a pair (in case there IS an error)
          # rescue SP::JSONAPI::Exceptions::GenericModelError => e
          #   [
          #     e.status,
          #     e.result
          #   ]
          # rescue Exception => e
          #   [
          #     SP::JSONAPI::Status::ERROR,
          #     get_error_response(path, e)
          #   ]
          # end
        end

        def request!(method, path, params)
          unwrap_request do
            do_request(method, path, params)
          end
        end

        def explicit_request!(exp_subentity_schema, exp_subentity_prefix, method, path, params)
          unwrap_request do
            explicit_do_request(exp_subentity_schema, exp_subentity_prefix, method, path, params)
          end
        end

        def specific_service_do_request!(method, path, params, service_params)
          unwrap_request do
            specific_service_do_request(method, path, params, service_params)
          end
        end

        protected

          def url(path) ; File.join(service.url, path) ; end

          def url_with_params_for_query(path, params)
            query = params_for_query(params)
            query_url = url(path)
            (query == '' || query == nil) ? query_url : query_url + (query_url.include?('?') ? '&' : '?') + query
          end

          def build_query(params)
            return '' if params.nil? || params == ''

            case params
            when Array
              params.map { |v| escape_value(v) }.join('&')
            when Hash
              params.map { |k, v| "#{k}=#{escape_value(v)}" }.join('&')
            else
              params.to_s
            end
          end

          def escape_value(value)
            return value unless value.is_a?(String)

            ERB::Util.url_encode(value)
          end

          def params_for_query(params)
            build_query(params)
          end

          def params_for_body(params)
            (params == '' || params == nil) ?  '' : params.to_json.gsub("'","''")
          end

          # unwrap_response SHOULD be implemented by each specialized adapter, and returns the request result as a JSONAPI string or hash and raises an exception if there was an error
          def unwrap_response(response)
            # As the method request() is EXACTLY the same as request!(), and it cannot be reverted without affecting lots of changes already made in the app's controllers...
            # Allow for response being both a [ status, result ] pair (as of old) OR a single result (as of now)
            if response.is_a?(Array)
              status = response[0].to_i
              result = response[1]
              result
            else
              response
            end
          end

          def error_response(path, error)
            {
              errors: [
                {
                  status: "#{SP::JSONAPI::Status::ERROR}",
                  code: error.message
                }
              ],
              links: { self: url(path) },
              jsonapi: { version: SP::JSONAPI::VERSION }
            }
          end

          # get_error_response MUST be implemented by each specialized adapter, and returns a JSONAPI error result as a string or hash
          def get_error_response(path, error) ; ; end

      end

    end
  end
end
