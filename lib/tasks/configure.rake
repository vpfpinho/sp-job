#require 'byebug'
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'

def create_directory (path)

  if ! Dir.exists?(path)
    if OS.mac?
      %x[mkdir -p #{path}]
    else
      %x[sudo mkdir -p #{path}]
    end
    if 0 != $?.exitstatus
      puts "      * Failed to create #{path}".red
    end
    if ! OS.mac?
      %x[sudo chown #{$user}:#{$group} #{path}]
    end
    if 0 != $?.exitstatus
      puts "      * Failed to change ownership to #{path}".red
    end
    if ! OS.mac?
      %x[sudo chmod 755 #{path}]
    end
    if 0 != $?.exitstatus
      puts "      * Failed to change permissions to #{path}".red
    end
  end

end

def diff_and_write (contents:, path:, diff: true, dry_run: false)
    if OS.mac? && ! Dir.exists?(File.dirname path)
      FileUtils::mkdir_p File.dirname path
    end
    if ! File.exists?(path)
      if OS.mac? || File.writable?(path)
        File.write(path,"")
      else
        %x[sudo touch #{path}]
      end
    end
    if true == diff
      tmp_file = Tempfile.new File.basename path
      FileUtils::mkdir_p File.dirname tmp_file
      File.write(tmp_file,contents)
      diff_contents = %x[diff -u #{path} #{tmp_file.path}]
      if 0 == $?.exitstatus
        puts "      * #{path} not changed".green
        return
      end
      puts "      * #{path} changed:".red
      puts diff_contents
    end
    puts "      * Writing #{path}".green
    unless dry_run
       if OS.mac? || File.writable?(path)
         File.write(path, contents)
       else
         %x[sudo chown #{$user}:#{$group} #{path}]
         File.write(path, contents)
         %x[sudo chown root:root #{path}]
       end
    end
    FileUtils.rm(tmp_file)
end

desc 'Update project configurations'
task :configure do

  class ::Hash
    def deep_merge(second)
        merger = proc { |key, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : Array === v1 && Array === v2 ? v1 | v2 : [:undefined, nil, :nil].include?(v2) ? v1 : v2 }
        self.merge(second.to_h, &merger)
    end
  end

  hostname = %x[hostname -s].strip
  @project = Dir.pwd
  @user_home = File.expand_path('~')
  diff_before_copy = true
  dry_run = false

  #
  # Pick file named 'hostname', or use 'developer' as basefile
  #
  if File.exists?("#{@project}/configure/#{hostname}.yml")
    conf = YAML.load_file("#{@project}/configure/#{hostname}.yml")
  else
    conf = YAML.load_file("#{@project}/configure/developer.yml")
  end

  #
  # Follow configuration dependencies and merge the configurations
  #
  configs = [ conf ]
  loop do
    break if conf['extends'].nil?
    conf = YAML.load_file("#{@project}/configure/#{conf['extends']}.yml")
    configs << conf
  end
  conf = configs[-1]
  (configs.size - 2).downto(0).each do |i|
    puts "Merging with #{configs[i]['extends']}"
    conf = conf.deep_merge(configs[i])
  end

  #
  # if check overides that turn off config inheritance
  #
  ['jobs!', 'nginx_broker!', 'nginx_epaper!'].each do |key|
    unless configs[0][key].nil?
      conf[key[0..-2]] = configs[0][key]
      conf.delete key
    end
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
  $user  = conf['user']
  $group = conf['group']

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
      conf['paths'][name] = path.sub('$project', @project)
      FileUtils.mkdir_p conf['paths'][name]
    elsif path.start_with? '$user_home'
      conf['paths'][name] = path.sub('$user_home', @user_home)
      FileUtils.mkdir_p conf['paths'][name]
    end
  end

  #
  # Transform the configuration into ostruct @config will be accessible to the ERB templates
  #
  @config = JSON.parse(conf.to_json, object_class: OpenStruct)

  #
  # Configure system, projects and user files 
  # 
  { 'system' => @config.prefix, 'project' => @project, 'user' => @user_home}.each do |src, dest|
    Dir.glob("#{@project}/configure/#{src}/**/*.erb") do |template|
      dst_file = template.sub("#{@project}/configure/#{src}", "#{dest}").sub(/\.erb$/, '')
      create_directory(File.dirname dst_file)
      diff_and_write(contents: ERB.new(File.read(template)).result(),
                     path: dst_file,
                     diff: true,
                     dry_run: true
      )
    end
  end

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
    if OS.mac?
      create_directory("/usr/local/var/lock/#{@job_name}/")
    end
    create_directory "#{@config.prefix}/etc/#{@job_name}"
    create_directory "#{@config.prefix}/var/log/#{@job_name}"
    diff_and_write(contents: JSON.pretty_generate(JSON.parse(ERB.new(File.read(template)).result())),
                   path: "#{@config.prefix}/etc/#{@job_name}/conf.json",
                   diff: diff_before_copy,
                   dry_run: dry_run
    )

    if File.exists? "#{@job_dir}/service.erb"
      template = "#{@job_dir}/service.erb"
    else
      template = "#{@config.paths.working_directory}/jobs/default.service.erb"
    end
    unless File.exists? template
      throw "Missing service file for #{@job_name}"
    end

    diff_and_write(contents: ERB.new(File.read(template)).result(),
                   path: "#{@config.prefix}/lib/systemd/system/#{@job_name}@.service",
                   diff: diff_before_copy,
                   dry_run: dry_run
    )

  end

end
