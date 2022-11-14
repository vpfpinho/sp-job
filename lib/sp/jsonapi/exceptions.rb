module SP
  module JSONAPI
    module Exceptions

      # JSONAPI service and configuration errors

      class ServiceSetupError < StandardError ; ; end
      class ServiceProtocolError < StandardError ; ; end
      class InvalidResourceConfigurationError < StandardError ; ; end
      class InvalidResourcePublisherError < StandardError ; ; end
      class DuplicateResourceError < StandardError ; ; end
      class SaveConfigurationError < StandardError ; ; end
      class InvalidJSONAPIKeyError < StandardError ; ; end

      # JSONAPI model querying errors

      class GenericModelError < StandardError

        attr_reader :id
        attr_reader :status
        attr_reader :result
        attr_reader :message
        attr_reader :code

        def initialize(result, nested = $!)
          @result = result
          errors = get_result_errors()
          @status = (errors.map { |error| error[:status].to_i }.max) || 403
          @message = errors.first[:detail]
          @code = errors.first[:code]
          nested ? super(@message, nested) : super(@message)
        end

        def internal_error
          errors = get_result_errors()
          if errors.length != 1
            @result.to_json
          else
            errors.first[:meta][:'internal-error'] if errors.first[:meta]
          end
        end

        def inspect()
          description = super()
          description = description + " (#{internal_error})" if internal_error
          description
        end

        def to_s
          @message
        end

        private

          def get_result_errors() ; (result.is_a?(Hash) ? result : (JSON.parse(result, symbolize_names: true)))[:errors] ; end

      end
    end
  end
end
