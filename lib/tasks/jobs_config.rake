require 'byebug'
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'

conf = {
  service_id: 'development',
  bundle_exec_cmd: '/usr/local/rvm/bin/rvm 2.1.5@toconline',
  prefix: '',
  paths: {
    uploads_storage:   '/Users/emi/work/cw/toconline/uploads',
    temporary_uploads: '/Users/emi/work/cw/toconline/uploads/tmp',
    working_directory: '/home/occ/webapps/toconline/current'    
  },
  redis: {
    master: {
      host: '127.0.0.1',
      port: 6379
    },
    casper: {
      host: '127.0.0.1',
      port: 6379
    }
  },
  db: {
    connection_string: 'host=localhost port=5432 dbname=toconline user=toconline password=toconline',
    min_queries_per_conn: 2000,
    max_queries_per_conn: 3000
  },
  rollbar: {
    token: 'bf308bcc35b943c0956f58c3d85b0caa',
    environment: 'development'
  },
  beanstalkd: {
    host: '127.0.0.1',
    port: 11300
  },
  cdn: {
     urls: {
      upload_internal: 'http://localhost:3003'
    }
  }, 
  jobs: [{
      name:        'uploaded-image-converter',
      description: 'Image scalling and conversion',
      instances: 1 
    }
  ]
}

desc 'Configure beanstalk jobs'
task :config_jobs do


  json = conf.to_json
  puts json
  prefix = '/usr/local'

  host = %x[hostname -s].strip
  puts "We are working on #{host}!!!"
  toconline_directory = '/Users/emi/work/cw/toconline'

  @config = JSON.parse(json, object_class: OpenStruct)

  @config.jobs.each do |job|
    @job_name        = job.name
    @job_description = job.description
    @job_dir         = "#{@config.paths.working_directory}/jobs/#{@job_name}"

    byebug

    if File.exists? "#{@job_dir}/conf.json.erb"
      template = "#{@job_dir}/conf.json.erb"
    else
      template = "#{@config.paths.working_directory}/jobs/default_conf.json.erb"
    end
    unless File.exists? template
      throw "Missing configuration file for #{@job_name}" 
    end
    contents = ERB.new(File.read(template), 0, '>').result()
    file = "#{prefix}/etc/#{job_name}/conf.json"
    puts("   writing configuration to #{file}")
    FileUtils::mkdir_p File.dirname file
    File.write(file,JSON.pretty_generate(JSON.parse(contents)))


    if File.exists? "#{@job_dir}/service.erb"
      template = "#{@job_dir}/service.erb"
    else
      template = "#{@config.paths.working_directory}/jobs/default_service.erb"
    end
    unless File.exists? template
      throw "Missing service file for #{@job_name}" 
    end
    contents = ERB.new(File.read(template), 0, '>').result()
    file = "#{prefix}/lib/systemd/system/#{@job_name}.service@1"
    puts("   writing configuration to #{file}")
    FileUtils::mkdir_p File.dirname file
    File.write(file,contents)

  end

end
