#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
#
# This file is part of sp-job.
#
# sp-job is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sp-job is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with sp-job.  If not, see <http://www.gnu.org/licenses/>.
#
# encoding: utf-8
#

require 'pg'
require 'openssl'

module SP
  module Job

    class XssAttack < ::StandardError
    end

    class PGConnection

      #
      # Public Attributes
      #
      attr_accessor :connection
      attr_reader   :config
      attr_reader   :xss_validators
      attr_writer   :logger
      attr_writer   :rollbar

      #
      # Prepare database connection configuration.
      #
      # @param owner
      # @param config
      #
      def initialize (owner:, config:, multithreaded: false)
        @mutex      = multithreaded ? Mutex.new : ::SP::Job::FauxMutex.new
        @owner      = owner
        @config     = config
        @connection = nil
        @treshold   = -1
        @counter    = 0
        @id_cache   = {}
        @post_connect_queries = nil
        min = @config[:min_queries_per_conn]
        max = @config[:max_queries_per_conn]
        if (!max.nil? && max > 0) || (!min.nil? && min > 0)
          @counter = 0
          new_min, new_max = [min, max].minmax
          new_min = new_min if new_min <= 0
          if new_min + new_min > 0
            @treshold = (new_min + (new_max - new_min) * rand).to_i
          else
            @treshold = new_min.to_i
          end
        end
        @transaction_open = false
        @rollbar = nil
        @logger  = nil
      end

      #
      # Establish a new database connection.
      #        Previous one ( if any ) will be closed first.
      #
      def connect ()
        @mutex.synchronize {
          _connect()
        }
      end

      #
      # Close currenly open database connection.
      #
      def disconnect (clear_post_connect_queries: false)
        @mutex.synchronize {
          if clear_post_connect_queries
            @post_connect_queries = nil
          end
          _disconnect()
        }
      end

      #
      # Close currenly open database connection if post_connect_queries were added.
      #
      def disconnect_if_has_post_connect_queries ()
        @mutex.synchronize {
          if @post_connect_queries != nil
            disconnect(clear_post_connect_queries: true)
          end
        }
      end

      #
      # Execute a prepared SQL statement with XSS validation
      #
      # @param query the SQL query with data binding
      # @param args all the args for the query
      # @return query result.
      #
      # @note only the args are checked against xss validation, query must be clean
      #
      def execp (query, *args)
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          unless @id_cache.has_key? query
            id = "p#{Digest::MD5.hexdigest(query)}"
            begin
              @connection.prepare(id, query)
            rescue PG::DuplicatePstatement => ds
              tmp_debug_str = ""
              @id_cache.each do | k, v |
                if v == id || k == query
                  tmp_debug_str += "#{v}: #{k}\n"
                  break
                end
              end
              if 0 == tmp_debug_str.length
                  tmp_debug_str = "~~~\nAll Entries:\n" + @id_cache.to_s
              else
                  tmp_debug_str = "~~~\nCached Entry:\n#{tmp_debug_str}"
              end
              tmp_debug_str += "~~~\nNew Entry: #{id}:#{query}\n"
              raise "#{ds.message}\n#{tmp_debug_str}"
            end
            @id_cache[query] = id
          else
            id = @id_cache[query]
          end

          if @xss_validators.length != 0
            args.each do |arg|
              _xss_validate(arg)
            end
          end

          @connection.exec_prepared(id, args)
        }
      end

      #
      # Execute a prepared SQL statement bypassing XSS validation
      #
      # @param query the SQL query with data binding
      # @param args all the args for the query
      # @return query result.
      #
      #
      def unsafe_execp (query, *args)
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          unless @id_cache.has_key? query
            id = "p#{Digest::MD5.hexdigest(query)}"
            begin
              @connection.prepare(id, query)
            rescue PG::DuplicatePstatement => ds
              tmp_debug_str = ""
              @id_cache.each do | k, v |
                if v == id || k == query
                  tmp_debug_str += "#{v}: #{k}\n"
                  break
                end
              end
              if 0 == tmp_debug_str.length
                  tmp_debug_str = "~~~\nAll Entries:\n" + @id_cache.to_s
              else
                  tmp_debug_str = "~~~\nCached Entry:\n#{tmp_debug_str}"
              end
              tmp_debug_str += "~~~\nNew Entry: #{id}:#{query}\n"
              raise "#{ds.message}\n#{tmp_debug_str}"
            end
            @id_cache[query] = id
          else
            id = @id_cache[query]
          end
          @connection.exec_prepared(id, args)
        }
      end

      #
      # Execute a normal SQL statement with xss validation
      #
      # @param query the SQL query with data binding
      # @param args all the args for the query
      # @return query result.
      #
      # @note in sprintf style the query is not validated
      #
      def exec (query, *args)
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          if args.length > 0
            if @xss_validators.length != 0
              args.each do |arg|
                _xss_validate(arg)
              end
            end
            @connection.exec(sprintf(query, *args))
          else
            _xss_validate(query)
            @connection.exec(query)
          end
        }
      end

      #
      # Execute a normal SQL statement bypassing xss validations
      #
      # @param query the SQL query with data binding
      # @param args all the args for the query
      # @return query result.
      #
      def unsafe_exec (query, *args)
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          if args.length > 0
            @connection.exec(sprintf(query, *args))
          else
            @connection.exec(query)
          end
        }
      end

      #
      # Escape an SQL string using the roman catholic method
      #
      # @param text the string to escape
      # @return escaped string
      #
      def escape (text)
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          @connection.escape_string(text)
        }
      end

      #
      # Call this to check if the database is not a production database where it's
      # dangerous to make development stuff. It checks the presence of a magic parameter
      # on the PG configuration that marks the database as a development arena
      #
      def safety_check ()
        SP::Duh::Db::safety_check(@connection)
      end

      #
      # Returns the configured connection string
      #
      def conn_str
        @config[:conn_str]
      end

      #
      # Call this to open a transaction
      #
      def begin
        @mutex.synchronize {
          if nil == @connection
            _connect()
          end
          _check_life_span()
          r = @connection.exec("BEGIN;")
          if PG::PGRES_COMMAND_OK != r.result_status
            raise "Unable to BEGIN a new transaction!"
          end
          @transaction_open = true
        }
      end

      #
      # Call this to commit the currently open transaction
      #
      def commit
        @mutex.synchronize {
          if nil != @connection && true == @transaction_open
            r = @connection.exec("COMMIT;")
            if PG::PGRES_COMMAND_OK != r.result_status
              raise "Unable to COMMIT a transaction!"
            end
            @transaction_open = false
          end
        }
      end

      #
      # Call this to open a transaction
      #
      def rollback
        @mutex.synchronize {
          if nil != @connection && true == @transaction_open
            r = @connection.exec("ROLLBACK;")
            if PG::PGRES_COMMAND_OK != r.result_status
              raise "Unable to ROLLBACK a transaction!"
            end
            @transaction_open = false
          end
        }
      end

      #
      # Call this to add a query to post_connect_queries, and execute it immediately if connected
      #
      def add_post_connect_query (query)
        @mutex.synchronize {
          if nil != @connection
            @connection.exec(query)
          end
          @post_connect_queries ||= Array.new
          @post_connect_queries.push(query)
        }
      end

      private

      def _connect ()
        _disconnect()
        @connection = PG.connect(@config[:conn_str])
        application_name = @config[:conn_str].match(/application_name=(.*)/im)
        unless application_name.nil?
          @connection.exec("SET application_name TO \"#{application_name[1]}\"")
        end
        if @post_connect_queries
          @post_connect_queries.each do |query|
            @connection.exec(query)
          end
        end
        _init_xss_validator();
      end

      def _disconnect ()
        @transaction_open = false
        if @connection.nil?
          return
        end

        begin
          if @id_cache.size
            @id_cache = {}
            @connection.exec("DEALLOCATE ALL")
          end
        ensure
          @connection.close
          @connection = nil
          @counter = 0
        end
      end

      #
      # Check connection life span
      #
      def _check_life_span ()
        if true == @transaction_open
          return
        end
        return unless @treshold > 0
        @counter += 1
        if @counter > @treshold
          _connect()
        end
      end

      #
      # Prepare a PosgreSQL connection.
      #
      # @param db  db config
      # @param app application name
      # @param sslmode: require, disable, verify-ca, verify-full
      #        see Table 31-1. SSL Mode Descriptions @https://www.postgresql.org/docs/9.1/libpq-ssl.html
      #
      def self.PostgreSQLConnectionString(db:, app:, sslmode: nil)
        if nil != sslmode
          return "postgres://#{db[:user]}:#{db[:password]}@#{db[:host]}:#{db[:port]}/#{db[:dbname]}?sslmode=#{sslmode}&application_name=#{app}"
        else
          return "postgres://#{db[:user]}:#{db[:password]}@#{db[:host]}:#{db[:port]}/#{db[:dbname]}?sslmode=#{db[:sslmode] || 'prefer'}&application_name=#{app}"
        end
      end

      def _xss_validate (str)
        if @xss_validators.length == 0
          return str
        end
        decoded = CGI.unescape(str.to_s)
        @xss_validators.each do |validator|
          if decoded.match validator
            @logger&.info "XssAttack #{str}".yellow
            e = XssAttack.new("invalid value: #{str.gsub('<', '?').gsub('>','?')}")
            @rollbar&.send(:error, e, "owner: #{@owner} str: #{str}")
            raise e
          end
        end
        str
      end

      def _init_xss_validator ()
        return if @xss_validators.is_a?(Array)
        @xss_validators = []
        begin
          rs = @connection.exec("SELECT current_setting('cloudware.xss_validators', TRUE)")
          if rs.ntuples == 1
            validators = rs.first['current_setting']
            if validators != nil && validators != ''
              validators = JSON.parse(validators)
              validators.each do |validator|
                re = Regexp.new(validator, Regexp::IGNORECASE | Regexp::EXTENDED | Regexp::MULTILINE)
                @xss_validators << re
              end
            end
          end
        rescue => e
          raise e
        end
      end

    end # end class 'PGConnection'

  end # module 'Job'
end # module 'SP'
