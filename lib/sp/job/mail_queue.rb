#
# Copyright (c) 2011-2017 Cloudware S.A. All rights reserved.
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
### IMPORTANT - serious this is important
# YOU must require 'rmagick' on the script that uses this class, should be used like this
#
# How to use this to implement a customized image conversion
#
# require 'rmagick'
# require 'sp-job'
# require 'sp/job/back_burner'
# require 'sp/job/mail_queue'
# 
# class CLASSNAME
#   extend SP::Job::Common
#   extend SP::Job::MailQueue
# 
#   def self.perform(job)
# 
#     ... Your code before sending the email
#
#     SP::Job::MailQueue.perform(job)
# 
#     ... your code after sending the email conversion ...
#
#   end
# end
# 
# Backburner.work
#

module SP
  module Job
    class MailQueue
      extend SP::Job::Common
      include Backburner::Queue
      queue 'mail-queue'
      queue_respond_timeout 30

      def self.perform (job)
        email = synchronous_send_email(
          body:    job[:body],
          to:      job[:to],
          subject: job[:subject]
        )
        logger.info "mailto: #{job[:to]} - #{job[:subject]}"
      end

      def self.on_failure (e, job)
        logger.info "Mail to #{job[:to]} failed"
      end

    end # MailQueue
  end # Job
end # SP
