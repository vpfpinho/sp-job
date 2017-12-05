# require 'byebug'
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'
require 'etc'

def safesudo(cmd)
  unless true == system(cmd)
    system("sudo #{cmd}")
  end
end

def create_directory (path)

  if ! Dir.exists?(path)
    if OS.mac?
      if path.match("^/usr/local/")
        info = Etc.getpwnam(Etc.getlogin)
        puts "\t* Creating '#{path}'...".yellow
        safesudo("mkdir -p #{path}")
        if 0 != $?.exitstatus
          puts "\t* Failed to create #{path}".red
        end
        next_parent_path = File.join("/usr/local", path.split(File::SEPARATOR).map {|x| x=="" ? File::SEPARATOR : x}[1..-1][2])
        if ! next_parent_path
          throw "Unable to create path #{path} - parent not found!"
        end
        safesudo("chown -R #{info.name}:#{Etc.getgrgid(info.gid).name} #{next_parent_path}")
        if 0 != $?.exitstatus
          puts "\t* Failed to change ownership to #{path}".red
        end
      else
        safesudo("mkdir -p #{path}")
        if 0 != $?.exitstatus
          puts "\t* Failed to create #{path}".red
        end
      end
    else
      if path.match("^/home/")
        safesudo("mkdir -p #{path}")
      else
        safesudo("mkdir -p #{path}")
      end
      if 0 != $?.exitstatus
        puts "\t* Failed to create #{path}".red
      end
    end
    if ! OS.mac? && !path.match("^/home/")
      safesudo("chown #{$user}:#{$group} #{path}")
    else
      safesudo("chown #{$user}:#{$group} #{path}")
    end
    if 0 != $?.exitstatus
      puts "\t* Failed to change ownership to #{path}".red
    end
    if ! OS.mac?  && !path.match("^/home/")
      safesudo("chmod 755 #{path}")
    else
      safesudo("chmod 755 #{path}")
    end
    if 0 != $?.exitstatus
      puts "\t* Failed to change permissions to #{path}".red
    end
  end

end

def diff_and_write (contents:, path:, diff: true, dry_run: false)

    if OS.mac?
      create_directory File.dirname path
    end

    if ! File.exists?(path)
      if contents.length == 0
        puts "\t* #{path} does not exist and it's empty, ignored".green
        return
      else
        safesudo("touch #{path}")
      end
    end

    if true == diff
      tmp_file = Tempfile.new File.basename path
      FileUtils::mkdir_p File.dirname tmp_file
      File.write(tmp_file,contents)
      diff_contents = %x[diff -u #{path} #{tmp_file.path} 2>/dev/null]
      if 0 == $?.exitstatus
        puts "\t* #{path} not changed".green
        return
      end
      if File.exists?(path)
        puts "\t* #{path} changed:".red
        puts diff_contents
      else
        puts "\t* #{path} does not exist. Will be created".blue
      end

    end
    puts "\t* Writing #{path}".green
    unless dry_run
       if OS.mac? || File.writable?(path) || path.match("^/home/")
         File.write(path, contents)
       else
         safesudo("chown #{$user}:#{$group} #{path}")
         File.write(path, contents)
         safesudo("chown root:root #{path}")
       end
    end
    FileUtils.rm(tmp_file)
end

def get_config

  hostname = %x[hostname -s].strip
  @project = Dir.pwd
  @user_home = File.expand_path('~')

  #
  # Pick file named 'hostname', or use 'developer' as basefile
  #
  if File.exists?("#{@project}/configure/#{hostname}.yml")
    conf = YAML.load_file("#{@project}/configure/#{hostname}.yml")
    conf['file_name'] = hostname
  else
    conf = YAML.load_file("#{@project}/configure/developer.yml")
    conf['file_name'] = 'developer'
  end

  #
  # Follow configuration dependencies and merge the configurations
  #
  configs = [ conf ]
  loop do
    break if conf['extends'].nil?
    ancestor = conf['extends']
    conf = YAML.load_file("#{@project}/configure/#{ancestor}.yml")
    conf['file_name'] = ancestor || 'developer'
    configs << conf
  end

  (configs.size - 2).downto(0).each do |i|
    puts "Step #{i}: merging '#{configs[i]['file_name']}' with '#{configs[i+1]['file_name']}'"
    configs[i].config_merge(configs[i+1])
  end

  conf = configs[0]

  #
  # Allow overide of project directory
  #
  conf['paths']['project'] ||= @project

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
  # Resolve project and user relative paths
  #
  conf['paths'].each do |name, path|
    if path.start_with? '$project'
      conf['paths'][name] = path.sub('$project', conf['paths']['project'] || @project)
    elsif path.start_with? '$user_home'
      conf['paths'][name] = path.sub('$user_home', @user_home)
    end
  end

  conf.clean_keys!

  ap conf
  return JSON.parse(conf.to_json, object_class: OpenStruct), conf
end

desc 'Update project configuration: action=overwrite => update system,user,project; action => hotfix update project only; other no change (dryrun)'
task :configure, [ :action ] do |task, args|

  # Monkey patch for configuration deep merge
  class ::Hash

    def config_merge (second)

      second.each do |skey, sval|
        if self.has_key?(skey+'!')
          self[skey] = self[skey+'!']
          self.delete(skey+'!')
          next
        elsif skey[-1] == '!'
          tkey = skey[0..-2]
          if self.has_key?(tkey)
            if Array === self[tkey] && Array === sval
              self[tkey] = self[tkey] | sval
            elsif Hash === self[tkey] && Hash === sval
              self[tkey].config_merge(sval)
            else
              raise "Error can't merge #{skey} with different types"
            end
          end
        end

        if ! self.has_key?(skey)
          self[skey] = sval
        else
          if Array === self[skey] && Array === sval
            self[skey] = self[skey] | sval
          elsif Hash === self[skey] && Hash === sval
            self[skey].config_merge(sval)
          end
        end
      end
    end

    def clean_keys!
      tmp = Hash.new

      self.each do |key, val|
        if Hash === val
          val.clean_keys!
        end

        if key[-1] == '!'
          tmp[key[0..-2]] = val
          self.delete(key)
        end
      end

      self.merge! tmp
    end

  end

  if args[:action] == 'overwrite'
    dry_run = false
    action = 'overwrite'
  elsif args[:action] == 'hotfix'
    dry_run = false
    action = 'hotfix'
  else
    dry_run = true
    action = 'dry-run'
  end

  #
  # Read the configuration into ostruct @config will be accessible to the ERB templates
  #
  @config, conf = get_config()

  #
  # Resolve project and user again to create the relative paths
  #
  conf['paths'].each do |name, path|
    if path.start_with? '$project'
      conf['paths'][name] = path.sub('$project', conf['paths']['project'] || @project)
      FileUtils.mkdir_p conf['paths'][name]
    elsif path.start_with? '$user_home'
      conf['paths'][name] = path.sub('$user_home', @user_home)
      FileUtils.mkdir_p conf['paths'][name]
    end
  end


  # Set helper variables on the task context
  $user  = @config.user
  $group = @config.group
  @project   = Dir.pwd
  @user_home = File.expand_path('~')
  diff_before_copy = true

  #
  # Create required paths
  #
  if @config.nginx_broker && @config.nginx_broker.nginx && @config.nginx_broker.nginx.paths
    @config.nginx_broker.nginx.paths.each do |path|
      if OS.mac? && @config.nginx_broker.nginx.suffix
        path = path.sub('nginx-broker', "nginx-broker#{@config.nginx_broker.nginx.suffix}")
      end
      create_directory "#{@config.prefix}#{path}"
    end
  end
  if @config.nginx_epaper && @config.nginx_epaper.nginx && @config.nginx_epaper.nginx.paths
    @config.nginx_epaper.nginx.paths.each do |path|
      create_directory "#{@config.prefix}#{path}"
    end
  end

  #
  # Configure system, projects and user files
  #
  locations = {}
  used_locations = []
  if action == 'dry-run' || action == 'overwrite'
    paths = { 'system' => @config.prefix, 'project' => @project, 'user' => @user_home}
  else
    paths = { 'project' => @project }
  end
  paths.each do |src, dest|
    puts "Configuring #{src.upcase}"

    # List all .erb files in hidden and visible folders
    erblist = Dir.glob("#{@project}/configure/#{src}/.**/*.erb") +
              Dir.glob("#{@project}/configure/#{src}/**/*.erb")

    erblist.each do |template|
      dst_file = template.sub("#{@project}/configure/#{src}", "#{dest}").sub(/\.erb$/, '')

      # developer exception
      if OS.mac? && @config.nginx_broker && @config.nginx_broker.nginx.suffix
        dst_file = dst_file.sub('nginx-broker', "nginx-broker#{@config.nginx_broker.nginx.suffix}")
      end

      # Nginx Locations must be filtered, only handle locations that are used
      m = /.*\.location$/.match(dst_file)
      if m
        locations[dst_file] = template
        next
      end

      # Filter nginx vhosts that do not have and entry, only install the vhosts that have an entry in nginx-xxxxx
      m = /.*(nginx-broker|nginx-epaper)\/conf\.d\/(.*)\.conf$/.match(dst_file)
      if m && m.size == 3
        key_l1 = m[1].gsub('-', '_')
        if conf[key_l1].nil? or conf[key_l1][m[2]].nil?
          puts "Filtered #{m[1]} - #{m[2]} - #{dst_file}".yellow
          next
        end
      end
      # do not touch config files on top folder if that nginx is not requested
      m =  /.*(nginx-broker|nginx-epaper)\/(.*)$/.match(dst_file)
      if m && m.size == 3
        key_l1 = m[1].gsub('-', '_')
        if conf[key_l1].nil?
          puts "Filtered #{m[1]} - #{m[2]} - #{dst_file}".yellow
          next
        end
      end

      # 2nd filtered
      if @config.erb_exclusion_list
        base_filename = File.basename(dst_file)
        if @config.erb_exclusion_list.include?(base_filename)
          puts "Filtered #{base_filename}".yellow
          next
        end
      end

      # puts "Expanding #{template}".red
      # Now expand the template
      file_contents = ERB.new(File.read(template), nil, '-').result()

      if /.*(nginx-broker|nginx-epaper)\/conf\.d\/(.*)\.conf$/.match(dst_file)
        includes = file_contents.scan(/^\s*include\s+conf\.d\/(.*)\.location\;/)
        includes.each do |loc|
          used_locations << loc[0]
        end
      end

      # Write text expanded configuration file
      create_directory(File.dirname dst_file)
      diff_and_write(contents: file_contents,
                     path: dst_file,
                     diff: diff_before_copy,
                     dry_run: dry_run
      )
    end
  end

  #
  # configure the nginx locations that are used
  #
  if action == 'dry-run' || action == 'overwrite'
    if used_locations.size
      puts "Configuring NGINX LOCATIONS"
      locations.each do |dst_file, template|
        m = /.*\/(.*).location$/.match dst_file
        if used_locations.include? m[1]
          # Write text expanded configuration file
          create_directory(File.dirname dst_file)
          diff_and_write(contents: ERB.new(File.read(template), nil, '-').result(),
                         path: dst_file,
                         diff: diff_before_copy,
                         dry_run: dry_run
          )
        end
      end
    end
  end

  #
  # Configure JOBS
  #
  if action == 'dry-run' || action == 'overwrite'
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
        throw "Missing #{template} => configuration file for #{@job_name}"
      end
      if OS.mac?
        create_directory("/usr/local/var/lock/#{@job_name}/")
      end
      create_directory "#{@config.prefix}/etc/#{@job_name}"
      create_directory "#{@config.prefix}/var/log/#{@job_name}"
      diff_and_write(contents: JSON.pretty_generate(JSON.parse(ERB.new(File.read(template), nil, '-').result())),
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
end
