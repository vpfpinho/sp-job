module SP
  module JSONAPI
    module Exceptions

      # JSONAPI service and configuration errors

      class ServiceSetupError < SP::Exceptions::GenericError ; ; end
      class ServiceProtocolError < SP::Exceptions::GenericDetailedError ; ; end
      class InvalidResourceConfigurationError < SP::Exceptions::GenericDetailedError ; ; end
      class InvalidResourcePublisherError < SP::Exceptions::GenericDetailedError ; ; end
      class DuplicateResourceError < SP::Exceptions::GenericDetailedError ; ; end
      class SaveConfigurationError < SP::Exceptions::GenericError ; ; end
      class InvalidJSONAPIKeyError < SP::Exceptions::GenericDetailedError ; ; end

      # JSONAPI model querying errors

      class GenericModelError < SP::Exceptions::GenericError

        attr_reader :id
        attr_reader :status
        attr_reader :result

        def initialize(result, nested = $!)
          @result = result
          errors = get_result_errors()
          @status = (errors.map { |error| error[:status].to_i }.max) || 403
          message = errors.first[:detail]
          super(message, nested)
        end

        def internal_error
          errors = get_result_errors()
          if errors.length != 1
            @result.to_json
          else
            errors.first[:meta]['internal-error'] if errors.first[:meta]
          end
        end

        def inspect()
          description = super()
          description = description + " (#{internal_error})" if internal_error
          description
        end

        private

          def get_result_errors() ; (result.is_a?(Hash) ? result : HashWithIndifferentAccess.new(JSON.parse(result)))[:errors] ; end

      end

    end
  end
end
