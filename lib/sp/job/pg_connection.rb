#
# Copyright (c) 2011-2016 Servicepartner LDA. All rights reserved.
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

    class PGConnection

      private

      #
      # Private Data
      #
      @owner      = nil
      @config     = nil
      @connection = nil
      @treshold   = -1
      @counter    = 0
      @statements = []

      public

      #
      # Public Attributes
      #
      attr_accessor :connection

      #
      # Prepare database connection configuration.
      #
      # @param owner
      # @param config
      #
      def initialize (owner:, config:)
        @owner      = owner
        @config     = config
        @connection         = nil
        @treshold   = -1
        @counter    = 0
        @statements = []
        min = @config[:min_queries_per_conn]
        max = @config[:max_queries_per_conn]
        if (!max.nil? && max > 0) || (!min.nil? && min > 0)
          @counter = 0
          new_min, new_max = [min, max].minmax
          new_min = new_min if new_min <= 0
          if new_min + new_min > 0
            @treshold = (new_min + (new_min - new_min) * rand).to_i
          else
            @treshold = new_min.to_i
          end
        end
      end

      #
      # Establish a new database connection.
      #        Previous one ( if any ) will be closed first.
      #
      def connect ()
        disconnect()
        @connection = PG.connect(@config[:conn_str])
      end

      #
      # Close currenly open database connection.
      #
      def disconnect ()
        if @connection.nil?
          return
        end
        while @statements.count > 0 do
            @connection.exec("DEALLOCATE #{@statements.pop()}")
        end
        @connection.close
        @connection = nil
        @counter = 0
      end

      #
      # Prepare an SQL statement.
      #
      # @param query
      #
      # @return Statement id.
      #
      def prepare_statement (query:)
        if nil == @connection
          connect()
        end
        id = "#{@owner}_#{Digest::MD5.hexdigest(query)}"
        if @statements.include? id
          return id
        else
          @statements << id
          @connection.prepare(@statements.last, query)
          return @statements.last
        end
      end

      #
      # Execute a previously prepared SQL statement.
      #
      # @param id
      # @param args
      #
      # @return PG result
      #
      def execute_statement (id:, args:)
        check_life_span()
        @connection.exec_prepared(id, args)
      end

      #
      # Destroy a previously prepared SQL statement.
      #
      # @param id
      # @param args
      #
      def dealloc_statement (id:)
        if nil == id
          while @statements.count > 0 do
              @connection.exec("DEALLOCATE #{@statements.pop()}")
          end
        else
          @statements.delete!(id)
          @connection.exec("DEALLOCATE #{id}")
        end
      end

      #
      # Execute a query,
      #
      # @param query
      #
      def query (query:)
        unless query.nil?
          check_life_span()
          @connection.exec(query)
        end
      end

      private

      #
      # Check connection life span
      #
      def check_life_span ()
        return unless @treshold > 0
        @counter += 1
        if @counter > @treshold
          connect()
        end
      end

    end # end class 'PGConnection'

  end # module 'Job'
end # module 'SP'