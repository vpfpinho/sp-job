#
# Copyright (c) 2011-2016 Cloudware S.A. All rights reserved.
#
# This file is part of sp-job.
#
# And this is the mix-in we'll apply to Job execution classes
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
require 'ffi'
require 'os'
require 'fileutils'

module SP
  module Job
    module Unique
      module File
        extend FFI::Library
        ffi_lib 'c'
        attach_function :puts, [ :string ], :int
        attach_function :mkstemps, [:string, :int], :int
        attach_function :fcntl, [:int, :int, :pointer], :int
        attach_function :close, [ :int ], :int
        unless OS.mac?
          attach_function :readlink, [ :string, :pointer, :int ], :int
        end

        #
        # Creates a uniquely named file inside the specified folder. The created file is empty
        #
        # @param a_folder Folder where the file will be created
        # @param a_suffix file suffix, warning must include the .
        # @return Absolute file path
        #
        def self.create (a_folder, a_extension)

          FileUtils.mkdir_p(a_folder) if !Dir.exist?(a_folder)
          
          _name = "#{a_folder}/_XXXXXX#{a_extension}"

          fd = ::SP::Job::Unique::File.mkstemps(_name, a_extension.length)

          if fd < 0
            return nil
          end

          if 'jruby' == RUBY_ENGINE
            ptr = FFI::MemoryPointer.new(:char, 8192)     # Assumes max path is less that this
            if OS.mac?
              r = ::SP::Job::Unique::File.fcntl(fd, 50, ptr) # 50 is F_GETPATH in OSX
            else
              r = ::SP::Job::Unique::File.readlink("/proc/self/fd/#{fd}", ptr, 8192)
              if r > 0 && r < 8192
                r = 0
              end
            end
            _name = ptr.read_string.force_encoding('UTF-8')
          end

          ::SP::Job::Unique::File.close(fd)

          return _name
        end

        #
        # Creates a uniquely named file inside the specified folder. The created file is empty
        #
        # @param folder Folder where the file will be created
        # @param name
        # @param extension
        # @return Absolute file path
        #
        def self.create_n (folder:, name:, extension:)

          FileUtils.mkdir_p(folder) if !Dir.exist?(folder)

          if nil != name
            _name = ::File.expand_path(::File.join(folder, "#{name}.XXXXXX.#{extension}"))
          else
            _name = ::File.expand_path(::File.join(folder, "XXXXXX.#{extension}"))
          end

          fd = ::SP::Job::Unique::File.mkstemps(_name, extension.length + 1)

          if fd < 0
            return nil
          end

          if 'jruby' == RUBY_ENGINE
            ptr = FFI::MemoryPointer.new(:char, 8192)     # Assumes max path is less that this
            if OS.mac?
              r = ::SP::Job::Unique::File.fcntl(fd, 50, ptr) # 50 is F_GETPATH in OSX
            else
              r = ::SP::Job::Unique::File.readlink("/proc/self/fd/#{fd}", ptr, 8192)
              if r > 0 && r < 8192
                r = 0
              end
            end
            _name = ptr.read_string.force_encoding('UTF-8')
          end

          ::SP::Job::Unique::File.close(fd)

          return _name
   
        end

      end
    end
  end
end
