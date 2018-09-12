# Usage (by a module or class belonging to a library or gem that publishes JSONAPI resources):
#
# In the module or class definition:
#
# include SP::JSONAPI::ResourcePublisher
# self.jsonapi_resources_root = "<path to the folder where the resources configurations are located>"

module SP
  module JSONAPI

    module ResourcePublisher

      def self.included(base)
        base.extend ClassMethods
        SP::JSONAPI::Configuration.add_publisher base
      end

      module ClassMethods
        attr_reader :jsonapi_resources_root
        private
          attr_writer :jsonapi_resources_root
      end

    end
  end
end
