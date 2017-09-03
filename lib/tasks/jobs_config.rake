#require 'byebug'
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'

desc 'Update project configurations'
task :configure do

  class ::Hash
    def deep_merge(second)
        merger = proc { |key, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : Array === v1 && Array === v2 ? v1 | v2 : [:undefined, nil, :nil].include?(v2) ? v1 : v2 }
        self.merge(second.to_h, &merger)
    end
  end

  hostname = %x[hostname -s].strip
  project = Dir.pwd

  #
  # Pick file named 'hostname', or use 'developer' as basefile
  #
  if File.exists?("#{project}/configure/#{hostname}.yml")
    conf = YAML.load_file("#{project}/configure/#{hostname}.yml")
  else
    conf = YAML.load_file("#{project}/configure/developer.yml")
  end

  #
  # Follow configuration dependencies and merge the configurations
  # 
  configs = [ conf ]
  loop do
    break if conf['extends'].nil?
    conf = YAML.load_file("#{project}/configure/#{conf['extends']}.yml")
    configs << conf
  end
  conf = configs[-1]
  (configs.size - 2).downto(0).each do |i|
    puts "Merging with #{configs[i]['extends']}"
    conf = conf.deep_merge(configs[i])
  end

  #
  # if job! is found it will replace the merged jobs
  #
  unless configs[0]['jobs!'].nil?
    conf['jobs'] = configs[0]['jobs!']
    conf.delete 'jobs!'
  end

  #
  # Resolve user and group if needed
  #
  if conf['user'].nil?
    conf['user'] = %x[id -u -nr].strip
  end
  if conf['group'].nil?
    conf['group'] = %x[id -g -nr].strip
  end

  #
  # Pre-cook the connection string
  #
  dbname = conf['db']['dbname']
  dbuser = conf['db']['user']
  dbhost = conf['db']['host']
  dbpass = conf['db']['password'] || ''
  conf['db']['connection_string'] = "host=#{dbhost} dbname=#{dbname} user=#{dbuser}#{dbpass.size != 0 ? ' password='+ dbpass : '' }"

  #
  # Resolve project relative paths
  #
  conf['paths'].each do |name, path|
    if path.start_with? '$project'
      conf['paths'][name] = path.sub('$project', project)
      FileUtils.mkdir_p conf['paths'][name]
    end
  end

  ap conf

  #
  # Transform the configuration into ostruct @config will be accessible to the ERB templates
  #
  @config = JSON.parse(conf.to_json, object_class: OpenStruct)

  #
  # Configure JOBS
  #
  puts "Configuring JOBS"
  @config.jobs.to_h.each do |name, job|
    @job_name        = name
    @job_description = "TODO Description"
    @job_dir         = "#{@config.paths.working_directory}/jobs/#{@job_name}"

    puts "  #{name}:"
    if File.exists? "#{@job_dir}/conf.json.erb"
      template = "#{@job_dir}/conf.json.erb"
    else
      template = "#{@config.paths.working_directory}/jobs/default_conf.json.erb"
    end
    unless File.exists? template
      throw "Missing configuration file for #{@job_name}" 
    end
    contents = ERB.new(File.read(template)).result()
    file = "#{@config.prefix}/etc/#{@job_name}/conf.json"
    puts("     writing job configuration to #{file}")
    FileUtils::mkdir_p File.dirname file
    File.write(file,JSON.pretty_generate(JSON.parse(contents)))

    if File.exists? "#{@job_dir}/service.erb"
      template = "#{@job_dir}/service.erb"
    else
      template = "#{@config.paths.working_directory}/jobs/default.service.erb"
    end
    unless File.exists? template
      throw "Missing service file for #{@job_name}" 
    end
    contents = ERB.new(File.read(template)).result()
    file = "#{@config.paths.staging_dir}/lib/systemd/system/#{@job_name}.service@1"
    puts("     writing job service unit to #{file}")
    FileUtils::mkdir_p File.dirname file
    File.write(file,contents)

  end

end
