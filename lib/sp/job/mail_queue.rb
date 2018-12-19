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
# require 'sp-job'
# require 'sp/job/back_burner'
# require 'sp/job/mail_queue'
#
# class MailQueue < ::SP::Job::MailQueue
#
#    #  Overide methods if needed!
#
# end
#
# Backburner.work('mail-queue')
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
          body:        job[:body],
          template:    job[:template],
          to:          job[:to],
          cc:          job[:cc],
          reply_to:    job[:reply_to],
          subject:     job[:subject],
          attachments: job[:attachments]
        )
        logger.info "mail - to: #{job[:to]} cc: #{job[:cc]} subject: #{job[:subject]}"
      end

      def self.on_failure (e, job)
        logger.info "Mail to #{job[:to]} failed"
      end

    end # MailQueue
  end # Job
end # SP
