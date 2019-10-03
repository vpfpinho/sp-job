#
# Copyright (c) 2011-2019 Cloudware S.A. All rights reserved.
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


require 'sp/job/http_client'

require 'sp/job/broker_upload_client'

require 'fileutils'

module SP
    module Job

      #
      # nginx-broker 'cdn-api' module client
      #
      class BrokerCDNBillingAPIClient

        #
        # Initialize a Broker CDN Billing API Client
        #
        # @param owner [REQUIRED] Client's owner - usually tube name - used for 'User-Agent' header.
        # @param url   [REQUIRED] Base URL
        #
        def initialize(owner:, url:)
            @url   = url
            @http  = ::SP::Job::HttpClient.new(owner: owner, headers: {
                'Content-Type' => 'application/vnd.api+json;charset=utf-8'
            }, mandatory_headers: {})
        end

        #
        # Retrieve an existing billing information.
        #
        # @param id [REQUIRED] Billing id, uint64.
        #
        # @return Billing data.
        #
        def get(id:)
            # make request
            response = @http.get(url: "#{@url}/billing/#{id}",
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
             # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

        #
        # Create a new billing entry.
        #
        # @param id    [REQUIRED] Billing id, uint64.
        # @param limit [REQUIRED] Maximum number of bytes usage limit for 'accounted' items.
        #
        # @return Billing data.
        #
        def create(id:, limit:)
            # make request
            response = @http.post(url: "#{@url}/billing", headers: nil, body: { data: { id: id, type: 'billing', attributes: { accounted_space_limit: limit } } }.to_json,
                expect: {
                    code: 204,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # nothing to return
            nil
        end

        #
        # Updates an existing billing entry.
        #
        # @param id    [REQUIRED] Billing id, uint64.
        # @param limit [REQUIRED] Maximum number of bytes usage limit for 'accounted' items.
        #
        # @return Billing data.
        #
        def update(id:, limit:)
            # make request
            response = @http.patch(url: "#{@url}/billing/#{id}", headers: nil, body: { data: { id: id, type: 'billing', attributes: { accounted_space_limit: limit } } }.to_json,
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

      end # class 'BrokerCDNBillingAPIClient'

      #
      # nginx-broker 'archive' module client
      #
      class BrokerArchiveClient

        #
        # Content Disposition X-HEADER helper.
        #
        class ContentDisposition

            attr_accessor :disposition
            attr_accessor :filename

            #
            # Initialize a 'X-CASPER' header helper for Content-Disposition.
            #
            # @param disposition One of 'inline' or 'attachment'
            # @param filename    Filename to use when disposition is 'attachment'.
            #
            def initialize(disposition:, filename: nil)
                @disposition = id
                @filename    = filename
            end

            #
            # @return New instance of \link ContentDisposition \link for 'inline' option.
            #
            def self.inline()
                ContentDisposition.new(disposition: 'inline')
            end

            #
            # Create a new instance of \link ContentDisposition \link for 'attachment' option.
            #
            # @param filename File name for download Content-Dispositon header.
            #                 When downloading a file it will be downloaded with the provided name ( if any ).
            #
            def self.attachment(filename: nil)
                ContentDisposition.new(disposition: 'attachment', filename: filename)
            end

            #
            # Translate this object into an hash with header data.
            #
            # @return { 'X-CASPER-CONTENT-DISPOSITION': <value> }
            #
            def header()
                if 'attachment' == @disposition
                    if nil != @filename
                        return { 'X-CASPER-CONTENT-DISPOSITION' => "attachment filename=#{@filename}" }
                    else
                        return { 'X-CASPER-CONTENT-DISPOSITION' => "attachment" }
                    end
                elsif 'inline' == @disposition
                    return { 'X-CASPER-CONTENT-DISPOSITION' => "inline" }
                end
                raise "Invalid content-disposition value '#{@disposition}' !"
            end

        end # class 'Content'

        #
        # Billing X-HEADER helper.
        #
        class Billing

            attr_accessor :id
            attr_accessor :type

            #
            # Initialize a 'X-CASPER' header helper for Billing
            #
            # @param id   Billing id.
            # @param type Billing type.
            #
            def initialize(id:, type:)
                @id   = id
                @type = type
            end

            #
            # Translate this object into an hash with header data.
            #
            # @return { 'X-CASPER-BILLING-ID': <value>, 'X-CASPER-BILLING-TYPE': <value> }
            #
            def headers()
                { 'X-CASPER-BILLING-ID' => @id, 'X-CASPER-BILLING-TYPE' => @type }
            end

        end # class 'Billing'

        #
        # Entity data holder.
        #
        class Entity

            attr_accessor :id
            attr_accessor :type

            #
            # Initialize an Entity data holder.
            #
            # @param id   Entity id.
            # @param type Entity type.
            #
            def initialize(id:, type:)
                @id   = id
                @type = type
            end

        end # class 'Entity'

        #
        # Initialize a 'archive' module client.
        #
        # @param owner   [REQUIRED] Client's owner - usually tube name - used for 'User-Agent' header.
        # @param url     [REQUIRED] Base URL
        # @param job     [REQUIRED] At least must contain entity_id, user_id, role_mask and module_mask attributes.
        # @param headers [OPTIONAL] Extra headers. - TMP until nginx-broker ( fs ) 0.2.xx is not released - TODO
        #
        def initialize(owner:, url:, job:, headers: nil)
            @url = url
            @headers = headers || {}
            x_casper_values = {
                entity_id:   job[:entity_id],
                user_id:     job[:user_id],
                role_mask:   job[:role_mask],
                module_mask: job[:module_mask],
            }
            x_casper_values.each do | k, v |
                if nil !=  v
                    @headers["X-CASPER-#{k.to_s.gsub('_', '-').upcase}"] = v
                end
            end
            @http  = ::SP::Job::HttpClient.new(owner: owner, headers: {}, mandatory_headers: {})
            @owner =  owner
        end

        #
        # Retrieve an existing archive.
        #
        # @param id [REQUIRED] Archive id, expected format aBBccccc[.ext]
        #
        # @return Archive body.
        #
        def get(id:)
            # make request
            response = @http.get(url: "#{@url}/#{id}", headers: make_request_headers())
            # return body only
            return response[:body]
        end

        #
        # Perform an HTTP POST request to 'Create' a new archive.
        #
        # @param entity       [REQUIRED] Entity info.
        #                                See \link Entity \link.
        # @param billing      [REQUIRED] Billing info.
        #                                See \link Billing \link.
        # @param permissions  [REQUIRED] Permissions human readable expression.
        # @param uri          [REQUIRED] Local file URI.
        # @param content_type [REQUIRED] Content-Type header value.
        # @param filename     [OPTIONAL] Alternative filename ( used when calling GET with Content-Disposition as attachment ).
        #
        # @return
        #
        # {
        #     "attributes": {
        #         "content-length": <uint64_t>,
        #         "content-type": <string>,
        #         "md5": <string>
        #     },
        #     "id": <string>,
        #     "type": <string>
        # }
        #
        # WHERE 'id' is newly 'created' archive ID.
        #
        def create(entity:, billing:, permissions:, uri:, content_type:, filename: nil)
            # set this request specific headers
            headers = { 'X-CASPER-ACCESS' => permissions, 'X-CASPER-ARCHIVED-BY' => @owner }
            headers.merge!(billing.headers())
            headers.merge!({'Content-Type' => content_type})
            if nil != filename
                headers.merge!({'X-CASPER-FILENAME' => filename})
            end
            # make request
            response = @http.post_file(uri: uri, to: @url, headers: make_request_headers(entity: entity, headers: headers),
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

        #
        # Perform an HTTP POST request to 'Update' an archive content.
        #
        # @param id           [REQUIRED] Archive ID.
        # @param uri          [REQUIRED] Local file URI.
        # @param content_type [REQUIRED] Content-Type header value.
        #
        # @return
        #
        # {
        #     "attributes": {
        #         "content-length": <uint64_t>,
        #         "content-type": <string>,
        #         "md5": <string>
        #     },
        #     "id": <string>,
        #     "type": <string>
        # }
        #
        # WHERE 'id' is the newly 'updated' archive ID.
        #
        def update(id:, uri:, content_type:)
            # set this request specific headers
            headers = { 'Content-Type' => content_type }
            # make request
            response = @http.put_file(uri: uri, to: "#{@url}/#{id}", headers: make_request_headers(headers: headers),
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

        #
        # Perform an HTTP POST request to 'Patch' an archive attributes.
        #
        # @param id           [REQUIRED] Archive ID.
        # @param permissions  [OPTIONAL] Permissions human readable expression.
        # @param filename     [OPTIONAL] Alternative filename ( used when calling GET with Content-Disposition as attachment ).
        #
        # @return
        #
        # {
        #     "attributes": {
        #         "content-length": <uint64_t>,
        #         "content-type": <string>,
        #         "md5": <string>,
        #         "name": <string> - OPTIONAL,
        #         "permissions": <string> - OPTIONAL
        #     },
        #     "id": <string>,
        #     "type": <string>
        # }
        #
        # WHERE 'id' is the newly 'patched' archive ID.
        #
        def patch(id:, permissions: nil, filename: nil)
            # set this request specific headers
            headers = {}
            if nil != permissions
                headers.merge!({'X-CASPER-ACCESS' => permissions})
            end
            if nil != filename
                headers.merge!({'X-CASPER-FILENAME' => filename})
            end
            if 0 == headers.count
                raise "Invalid call to 'patch' method - no data to patch!"
            end
            # make request
            response = @http.patch(url: "#{@url}/#{id}", headers: make_request_headers(headers: headers), body: nil,
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

        #
        # Perform an HTTP POST request to 'Delete' an archive.
        #
        # @param id [REQUIRED] Archive ID.
        #
        # @return nil ( 204 - No content )
        #
        def delete(id:)
            @http.delete(url: "#{@url}/#{id}", headers: make_request_headers(),
                expect: {
                    code: 204
                }
            )
            nil
        end

        #
        # Perform an HTTP POST request to 'Move' a previously uploaded archive.
        #
        # @param entity       [REQUIRED] Entity info.
        #                                See \link Entity \link.
        # @param billing      [REQUIRED] Billing info.
        #                                See \link Billing \link.
        # @param permissions  [REQUIRED] Permissions human readable expression.
        # @param uri          [REQUIRED] Partial URI YYYY-MM-DDDD/aBBcccccc[.ext].
        # @param content_type [REQUIRED] Content-Type header value.
        # @param filename     [OPTIONAL] Alternative filename ( used when calling GET with Content-Disposition as attachment ).
        #
        # @return
        #
        # {
        #     "attributes": {
        #         "content-length": <uint64_t>,
        #         "content-type": <string>,
        #         "md5": <string>,
        #         "name": <string> - OPTIONAL,
        #         "permissions": <string> - OPTIONAL
        #     },
        #     "id": <string>,
        #     "type": <string>
        # }
        #
        # WHERE 'id' is the newly 'moved' archive ID.
        #
        def move(entity:, billing:, permissions:, uri:, content_type:, filename: nil)
            # set this request specific headers
            headers = {
                'Content-Type' => content_type,
                'X-CASPER-ACCESS' => permissions ,
                'X-CASPER-MOVES-URI' => uri
            }
            headers.merge!(billing.headers())
            if nil != filename
                headers.merge!({'X-CASPER-FILENAME' => filename})
            end
            # make request
            response = @http.post(url: @url, headers: make_request_headers(entity: entity, headers: headers), body: nil,
                expect: {
                    code: 200,
                    content: {
                        type: 'application/vnd.api+json;charset=utf-8'
                    }
                }
            )
            # return body only
            JSON.parse(response[:body], symbolize_names: true)
        end

      private

        #
        # Merge headers for a request.
        #
        # @param entity [OPTIONAL] See \link Entity \link.
        #
        # @return Filtered headers by entity ( if any )
        #
        def make_request_headers(entity: nil, headers: nil)
            # start with mandatory headers
            if nil == headers
                _headers = @headers
            else
                _headers = @headers.merge(headers)
            end
            # merge specific request headers
            if nil != headers
                _headers.merge!(headers)
            end
            # remove unwanted headers
            if nil != entity
                if entity.type == :user
                    _headers.merge!({'X-CASPER-USER-ID' => entity.id})
                    _headers.delete('X-CASPER-ENTITY-ID')
                elsif entity.type == :company
                    _headers.merge!({'X-CASPER-ENTITY-ID' => entity.id})
                    _headers.delete('X-CASPER-USER-ID')
                end
            end
            # done
            _headers
        end

        #
        # Helper method to test this client.
        #
        # @param owner  [REQUIRED] Client's owner - usually tube name - used for 'User-Agent' header.
        # @param urls   [REQUIRED] { archive: <string>, upload: <string> }
        # @param tmp    [REQUIRED] Temporary path.
        # @param job    [REQUIRED] At least must contain entity_id, user_id, role_mask and module_mask attributes.
        # @param output [REQUIRED] Reserved.
        #
        def self.test(owner:, urls:, tmp:, job:, output:)

            error_count = 0
            conn_options = {}

            puts "--- --- --- --- --- --- --- --- --- --- ---"
            puts "#{self.name()} ~~ RUNNING ~~".purple
            puts "--- --- --- --- --- --- --- --- --- --- ---"

            # create client
            client = BrokerArchiveClient.new(owner: self.name(), url: urls[:archive], job: job)
            # create temporary test files
            files = {
                create: {
                    uri: "/tmp/broker-archive-client-test-file-create.txt",
                    content: "broker-archive-client-test-file create file content!",
                    :'content-type' => "application/text"
                },
                update: {
                    uri: "/tmp/broker-archive-client-test-file-update.txt",
                    content: "{\"data\":\"broker-archive-client-test-file updated file content!\"}",
                    :'content-type' => "application/json"
                }
            }
            files.each do | k, v |
                File.open(v[:uri], "w") { |file| file.puts "#{v[:content]}"}
            end
            #
            entity  = BrokerArchiveClient::Entity.new(id: job[:user_id], type: :user)
            billing = BrokerArchiveClient::Billing.new(id: job[:entity_id], type: 'archive')
            #
            responses = {}
            # test CREATE method
            error_count+= ::SP::Job::HttpClient.run_test(verb: "CREATE", output: output) do
                responses[:create] = client.create(entity: entity, billing: billing, permissions: "rw = user_id == #{job[:user_id]};",
                                                   uri: files[:create][:uri],
                                                   content_type: files[:create][:'content-type'],
                                                   filename: nil
                )
            end

            # test GET method
            error_count+= ::SP::Job::HttpClient.run_test(verb: "GET", output: output) do
                responses[:get] = client.get(id: responses[:create][:id])
                # if reached here, response is OK
                { code: 200, body: responses[:get] }
            end

            # test UPDATE method
            error_count+= ::SP::Job::HttpClient.run_test(verb: "UPDATE", output: output) do
                responses[:update] = client.update(id: responses[:create][:id], uri: files[:update][:uri], content_type:files[:update][:'content-type'] )
                responses[:update]
            end
            # test PATCH method
            error_count+= ::SP::Job::HttpClient.run_test(verb: "PATCH", output: output) do
                responses[:patch] = client.patch(id: responses[:update][:id], permissions: "drw = user_id == #{job[:user_id]};")
                responses[:patch]
            end
            # test DELETE method
            error_count+= ::SP::Job::HttpClient.run_test(verb: "DELETE", output: output) do
                responses[:delete] = client.delete(id: responses[:patch][:id])
                # if reached here, response is No Content
                { code: 204, body: '' }
            end

            if 'jruby' != RUBY_ENGINE
                # test UPLOAD internal method
                error_count+= ::SP::Job::HttpClient.run_test(verb: "UPLOAD", output: output) do
                    responses[:upload] = ::SP::Job::BrokerUploadClient.new(owner: self.name(), url: urls[:upload]).upload(body: 'UPLOADED TEST DATA')
                    responses[:upload]
                end
                # test MOVE method
                error_count+= ::SP::Job::HttpClient.run_test(verb: "MOVE", output: output) do
                    responses[:move] = client.move(entity: entity, billing: billing, permissions: "drw = user_id == #{job[:user_id]};",
                                                   uri: responses[:upload][:file], content_type: 'application/octet-stream',
                                                   filename: nil
                    )
                    responses[:move]
                end
                # test GET 'moved' file
                error_count+= ::SP::Job::HttpClient.run_test(verb: "GET", output: output) do
                    responses[:get] = client.get(id: responses[:move])
                    # if reached here, response is OK
                    { code: 200, body: responses[:get] }
                end
            end

            puts "--- --- --- --- --- --- --- --- --- --- ---"
            print "#{self.name()}".purple
            print " ~~ %s ~~" % [error_count > 0 ? 'FAILED'.red : 'PASS'.green]
            print "\n"
            puts "--- --- --- --- --- --- --- --- --- --- ---"

        end # self.test

      end # class 'BrokerArchiveClient'

    end # module Job
end #module SP
