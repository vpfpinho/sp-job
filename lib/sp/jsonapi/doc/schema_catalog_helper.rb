module SP
  module JSONAPI
    module Doc

      class SchemaCatalogHelper

        def initialize(pg_connection)
          @pg_connection = pg_connection
          @default_schema = get_db_first_sharded_schema()
          clear_settings
        end

        def clear_settings ; @settings = {} ; @attrs = nil ; end
        def add_setting(setting, value) ; @settings[setting.to_sym] = value ; end
        def get_settings
          @settings.merge({
            schema: (@settings[:use_schema] ? @default_schema : 'public')
          })
        end

        def get_attribute(name)
          if @attrs.nil?
            if get_settings[:table_name].nil?
              @attrs = get_db_function_attribute_definitions(get_settings[:schema], get_settings[:function_name])
            else
              @attrs = get_db_table_attribute_definitions(get_settings[:schema], get_settings[:table_name])
            end
          end
          @attrs[name.to_s]
        end

        private

          def get_db_first_sharded_schema
            result = @pg_connection.exec %q[
              SELECT
                c.schema_name
              FROM
                public.companies c
              WHERE
                c.use_sharded_company = true
              LIMIT 1
            ]
            result[0]['schema_name']
          end

          def get_db_table_attribute_definitions(schema, table_name)
            return {} if schema.nil? || table_name.nil?
            result = @pg_connection.exec %Q[
              SELECT
                t.tablename::TEXT AS object_name,
                a.attname,
                pg_catalog.format_type(a.atttypid, a.atttypmod),
                (SELECT substring(pg_catalog.pg_get_expr(d.adbin, d.adrelid) for 128) FROM pg_catalog.pg_attrdef d WHERE d.adrelid = a.attrelid AND d.adnum = a.attnum AND a.atthasdef) AS default_value,
                a.attnotnull
              FROM pg_catalog.pg_attribute a
                JOIN pg_catalog.pg_class c ON a.attrelid = c.oid
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_tables t ON c.oid = (t.schemaname || '.' || t.tablename)::regclass::oid
              WHERE a.attnum > 0
                AND NOT a.attisdropped
                AND n.nspname = '#{schema}'
                AND t.tablename = '#{table_name}'
            ]
            definitions = {}
            result.each { |a| definitions.merge!({ a['attname'] => a })  }
            definitions
          end

          def get_db_function_attribute_definitions(schema, function_name)
            return {} if schema.nil? || function_name.nil?
            result = @pg_connection.exec %Q[
              SELECT
                trim(split_part(regexp_replace(p.argument, E'^OUT ', ''), ' ', 1)) AS attname,
                trim(split_part(regexp_replace(p.argument, E'^OUT ', ''), ' ', 2)) AS format_type
              FROM (
                SELECT
                  trim(unnest(regexp_split_to_array(pg_catalog.pg_get_function_arguments(p.oid), E','))) as argument
                FROM pg_catalog.pg_proc p
                     LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                WHERE p.proname ~ '^(#{function_name})$'
                  AND n.nspname ~ '^(#{schema})$'
              ) p
              WHERE
                CASE WHEN p.argument ~ '^OUT' THEN true ELSE false END = true
            ]
            definitions = {}
            result.each { |a| definitions.merge!({ a['attname'] => a })  }
            definitions
          end
      end

    end
  end
end
