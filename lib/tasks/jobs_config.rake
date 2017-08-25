# require 'byebug'
require 'json'
require 'erb'
require 'ostruct'

conf = {
  service_id: 'development',
  paths: {
    temporary_files: '/tmp',
    uploads_storage: '/Users/emi/work/cw/toconline/uploads',
    temporary_uploads: '/Users/emi/work/cw/toconline/uploads/tmp'
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
  ham: [ { a: 1, b: 2 }, 2, 4]
}

desc 'Configure beanstalk jobs'
task :config_jobs do


  json = conf.to_json
  prefix = '/usr/local'

  host = %x[hostname -s].strip
  puts "We are working on #{host}!!!"
  toconline_directory = '/Users/emi/work/cw/toconline'

  @config = JSON.parse(json, object_class: OpenStruct)

  #debugger

  Dir.glob("#{toconline_directory}/jobs/*").each do |job|
    job_name = File.basename(job)
    puts("#{host}: #{job_name}")
    if File.exists? "#{job}/conf.json.erb"
      file     = "#{prefix}/etc/#{job_name}/conf.json"
      contents = ERB.new(File.read("#{job}/conf.json.erb")).result()
      puts("   writing configuration to #{file}")
      File.write(file,contents)
    end
  end

end
