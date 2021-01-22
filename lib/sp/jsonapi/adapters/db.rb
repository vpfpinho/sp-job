module SP
  module JSONAPI
    module Adapters

      class Db < RawDb

        protected

          def get_error_response(path, error)
            error_response(path, error)
          end

        private

          def is_error?(result) ; result[:errors] && result[:errors].any? ; end

          def process_result(result)
            response = JSON.parse(result['response'], symbolize_names: true)
            raise SP::JSONAPI::Exceptions::GenericModelError.new(response) if is_error?(response)
            [ result['http_status'], response ]
          end

      end

    end
  end
end
