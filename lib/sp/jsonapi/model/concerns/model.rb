require 'sp/jsonapi/model/concerns/attributes'
require 'sp/jsonapi/model/concerns/serialization'
require 'sp/jsonapi/model/concerns/persistence'

module SP
  module JSONAPI
    module Model
      module Concerns
        module Model

          def self.included klass
            klass.extend ClassMethods

            klass.class_eval do
              include Attributes
              include Serialization
              include Persistence
            end
          end

          module ClassMethods

            def inspect
              "#{super}(#{self.attributes.join(', ')})"
            end
          end

          # Returns the contents of the record as a nicely formatted string.
          def inspect
            # attrs = self.class.attributes
            inspection = self.class.attributes.collect { |name| "#{name}: #{attribute_for_inspect(name)}" }.compact.join(", ")
            "#<#{self.class} #{inspection}>"
          end

        end
      end
    end
  end
end
