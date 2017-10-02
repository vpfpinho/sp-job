#require 'byebug'
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'
require 'etc'

def create_directory (path)

  if ! Dir.exists?(path)
    if OS.mac?
      if path.match("^/usr/local/")
        info = Etc.getpwnam(Etc.getlogin)
        puts "      * Creating '#{path}'...".yellow
        %x[sudo mkdir -p #{path}]
        if 0 != $?.exitstatus
          puts "      * Failed to create #{path}".red
        end
        next_parent_path = File.join("/usr/local", path.split(File::SEPARATOR).map {|x| x=="" ? File::SEPARATOR : x}[1..-1][2])
        if ! next_parent_path
          throw "Unable to create path #{path} - parent not found!"
        end
        %x[sudo chown -R #{info.name}:#{Etc.getgrgid(info.gid).name} #{next_parent_path}]
        if 0 != $?.exitstatus
          puts "      * Failed to change ownership to #{path}".red
        end
      else
        %x[mkdir -p #{path}]
        if 0 != $?.exitstatus
          puts "      * Failed to create #{path}".red
        end
      end
    else
      if path.match("^/home/")
        %x[mkdir -p #{path}]
      else
        %x[sudo mkdir -p #{path}]
      end
      if 0 != $?.exitstatus
        puts "      * Failed to create #{path}".red
      end
    end
    if ! OS.mac? && !path.match("^/home/")
      %x[sudo chown #{$user}:#{$group} #{path}]
    else
      %x[chown #{$user}:#{$group} #{path}]
    end
    if 0 != $?.exitstatus
      puts "      * Failed to change ownership to #{path}".red
    end
    if ! OS.mac?  && !path.match("^/home/")
      %x[sudo chmod 755 #{path}]
    else
      %x[chmod 755 #{path}]
    end
    if 0 != $?.exitstatus
      puts "      * Failed to change permissions to #{path}".red
    end
  end

end

def diff_and_write (contents:, path:, diff: true, dry_run: false)
    if OS.mac?
      create_directory File.dirname path
    end
    if ! File.exists?(path)
      if OS.mac? || File.writable?(path) || path.match("^/home/")
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
       if OS.mac? || File.writable?(path) || path.match("^/home/")
         File.write(path, contents)
       else
         %x[sudo chown #{$user}:#{$group} #{path}]
         File.write(path, contents)
         %x[sudo chown root:root #{path}]
       end
    end
    FileUtils.rm(tmp_file)
end

desc 'Update project configuration: action=overwrite => update system,user,project; action => hotfix update project only; other no change (dryrun)'
task :configure, [ :action ] do |task, args|

  class ::Hash

    def deep_merge (second)

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
              self[tkey].deep_merge(sval)
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
            self[skey].deep_merge(sval)
          end
        end
      end
    end

  end

  hostname = %x[hostname -s].strip
  @project = Dir.pwd
  @user_home = File.expand_path('~')
  diff_before_copy = true

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
    conf = YAML.load_file("#{@project}/configure/#{conf['extends']}.yml")
    conf['file_name'] = conf['extends'] || 'developer'
    configs << conf
  end

  (configs.size - 2).downto(0).each do |i|
    puts "Step #{i}: merging '#{configs[i]['file_name']}' with '#{configs[i+1]['file_name']}'"
    configs[i].deep_merge(configs[i+1])
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
  # Resolve project and user relative paths
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


  #
  # Transform the configuration into ostruct @config will be accessible to the ERB templates
  #
  @config = JSON.parse(conf.to_json, object_class: OpenStruct)

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
    paths = { 'system' => @config.prefix, 'project' => @project} # , 'user' => @user_home TODO
  else
    paths = { 'project' => @project }
  end
  paths.each do |src, dest|
    puts "Configuring #{src.upcase}"
    Dir.glob("#{@project}/configure/#{src}/**/*.erb") do |template|
      dst_file = template.sub("#{@project}/configure/#{src}", "#{dest}").sub(/\.erb$/, '')

      # developer exception
      if OS.mac? && @config.nginx_broker.nginx.suffix
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
        throw "Missing configuration file for #{@job_name}"
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
