require 'sp/jsonapi/doc/victor_pinus_metadata_format_parser'
require 'sp/jsonapi/doc/apidoc_documentation_format_generator'

module SP
  module JSONAPI
    module Doc

      class Generator

        def initialize(pg_connection)
          @pg_connection = pg_connection
        end

        def generate(resource_publisher, version, doc_folder_path = File.join(Dir.pwd, 'apidoc'))
          # Load the JSONAPI resources from the given publishers
          @parser = SP::JSONAPI::Doc::VictorPinusMetadataFormatParser.new(@pg_connection)
          @parser.parse(resource_publisher)
          # Generate the resources documentation
          @generator = SP::JSONAPI::Doc::ApidocDocumentationFormatGenerator.new
          @generator.generate(@parser, version, doc_folder_path)
          # Regenerate the documentation site
          _log "Generating the documentation site in #{doc_folder_path}", "JSONAPI::Doc::Generator"
          `(cd #{doc_folder_path} && apidoc)`
        end

      end

    end
  end
end
