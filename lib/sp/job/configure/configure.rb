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
require 'json'
require 'erb'
require 'ostruct'
require 'awesome_print'
require 'os'
require 'fileutils'
require 'tempfile'
require 'etc'

require 'byebug'

puts "Running configure poison".red

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

end # Hash monkey patch

class SpDataStruct < OpenStruct

  def self.to_hash_sp (object)
    hash = {}
    object.each_pair do |key, value|
      if value.is_a?(SpDataStruct)
        hash[key] = SpDataStruct::to_hash_sp(value)
      elsif value.is_a?(Array)
        hash[key] = []
        value.each do |member|
          if member.is_a?(SpDataStruct)
            hash[key] << SpDataStruct::to_hash_sp(member)
          else
            hash[key] << member
          end
        end
      else
        hash[key] = value
      end
    end
    hash
  end

  def to_json
    SpDataStruct::to_hash_sp(self).to_json
  end

end

def self.safesudo(cmd)
  unless true == system(cmd)
    system("sudo #{cmd}")
  end
end

def self.create_directory (path)

  if ! Dir.exist?(path)
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

def self.diff_and_write (contents:, path:, diff: true, dry_run: false)

  if contents.length == 0
    puts "\t* contents for #{path} is empty, ignored, we don't write empty files".green
    return
  end

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

def self.pg_conn_string (db)
  "host=#{db.host} port=#{db.port} dbname=#{db.dbname} user=#{db.user}#{db.password != nil && db.password.size != 0 ? ' password='+ db.password : '' }"
end

def self.pg_conn_str (db:, application:)
  "host=#{db.host} port=#{db.port} dbname=#{db.dbname} user=#{db.user}#{db.password != nil && db.password.size != 0 ? ' password='+ db.password : '' } application_name=#{application}"
end

def self.expand_template (template, pretty_json: false)
  begin
    contents = ERB.new(File.read(template), nil, '-').result()
    if pretty_json
      JSON.pretty_generate(JSON.parse(contents))
    else
      contents
    end
  rescue Exception => e
    puts "Expansion of #{template} failed".yellow
    puts e.message.red
    exit
  end
end

def self.get_config (args)
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
  # Pre-cook the connection string # TODO remove this after Hydra goes live
  #
  if conf['db']
    dbname = conf['db']['dbname']
    dbuser = conf['db']['user']
    dbhost = conf['db']['host']
    dbport = conf['db']['port'] || 5432
    dbpass = conf['db']['password'] || ''
    conf['db']['connection_string'] = "host=#{dbhost} port=#{dbport} dbname=#{dbname} user=#{dbuser}#{dbpass.size != 0 ? ' password='+ dbpass : '' }"
  end

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

  #
  # Read optional brand information
  #
  if conf['product']
    brand_file = "#{@project}/configure/products/#{conf['product']}/brands.yml"
    if File.exists?(brand_file)
      brands = YAML.load_file(brand_file)
    end
    conf['brands'] = brands['brands']

    application_file = "#{@project}/configure/products/#{conf['product']}/application.yml"
    if File.exists?(application_file)
      conf['application'] = YAML.load_file(application_file)
    end
  end

  conf.clean_keys!

  if args[:print_config]
    puts conf.to_yaml(:Indent => 4).white
  end
  return JSON.parse(conf.to_json, object_class: SpDataStruct), conf
end

def self.run_configure (args)

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
  @config, conf = get_config(args)

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
      if @config.nginx_broker.nginx.suffix
        path = path.sub('nginx-broker', "nginx-broker#{@config.nginx_broker.nginx.suffix}")
      end
      create_directory "#{@config.prefix}#{path}"
    end
  end
  if @config.nginx_epaper && @config.nginx_epaper.nginx && @config.nginx_epaper.nginx.paths
    @config.nginx_epaper.nginx.paths.each do |path|
      if @config.nginx_epaper.nginx.suffix
        path = path.sub('nginx-epaper', "nginx-epaper#{@config.nginx_epaper.nginx.suffix}")
      end
      create_directory "#{@config.prefix}#{path}"
    end
  end
  if OS.mac? && @config.jobs
    @config.jobs.each do |job|
      if job.paths
        job.paths.each do |path|
          puts "Creating directory #{@config.prefix}#{path}"
          create_directory "#{@config.prefix}#{path}"
        end
      end
    end
  end

  #
  # Copy /usr/share/ files to suffix directory
  #
  OS.mac? ? local_dir = '/local' : local_dir = ''
  if @config.nginx_broker && @config.nginx_broker.nginx && @config.nginx_broker.nginx.suffix
    create_directory("/usr#{local_dir}/share/nginx-broker#{@config.nginx_broker.nginx.suffix}")
    safesudo("cp /usr#{local_dir}/share/nginx-broker/i18.json /usr#{local_dir}/share/nginx-broker#{@config.nginx_broker.nginx.suffix}/")
  end

  if @config.nginx_epaper &&  @config.nginx_epaper.nginx && @config.nginx_epaper.nginx.suffix
    create_directory("/usr#{local_dir}/share/nginx-epaper#{@config.nginx_epaper.nginx.suffix}/fonts/ttf/dejavu")
    safesudo("cp -v -f /usr#{local_dir}/share/nginx-epaper/fonts/ttf/dejavu/* /usr#{local_dir}/share/nginx-epaper#{@config.nginx_epaper.nginx.suffix}/fonts/ttf/dejavu")
  end

  #
  # Configure system, projects and user files
  #
  hostname = %x[hostname -s].strip
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

      # do not configure motd
      if dst_file == '/etc/motd'
        if OS.mac? || ! @config.motd || ! @config.motd[hostname.to_sym]
          next
        end
      end

      # developer exception
      if dst_file.include?('nb-xattr') && @config.nginx_broker && @config.nginx_broker.nginx && @config.nginx_broker.nginx.suffix
        dst_file = dst_file.sub('nb-xattr', "nb-xattr#{@config.nginx_broker.nginx.suffix}")
      end
      if dst_file.include?('nginx-broker') && @config.nginx_broker && @config.nginx_broker.nginx && @config.nginx_broker.nginx.suffix
        dst_file = dst_file.sub('nginx-broker', "nginx-broker#{@config.nginx_broker.nginx.suffix}")
      end
      if dst_file.include?('nginx-epaper') && @config.nginx_epaper && @config.nginx_epaper.nginx && @config.nginx_epaper.nginx.suffix
        dst_file = dst_file.sub('nginx-epaper', "nginx-epaper#{@config.nginx_epaper.nginx.suffix}")
      end

      # Nginx Locations must be filtered, only handle locations that are used
      m = /.*\.location$/.match(dst_file)
      if m
        locations[dst_file] = template
        next
      end

      # Filter nginx vhosts that do not have and entry, only install the vhosts that have an entry in nginx-xxxxx
      m = /.*(nginx-broker|nginx-epaper)[^\/]*?\/conf.d\/(.*)\.conf$/.match(dst_file)
      if m && m.size == 3
        key_l1 = m[1].gsub('-', '_')
        if conf[key_l1].nil? or !conf[key_l1].key?(m[2])
          puts "Filtered #{m[1]} - #{m[2]} - #{dst_file}"
          next
        end
      end
      # do not touch config files on top folder if that nginx is not requested
      m =  /.*(nginx-broker|nginx-epaper)[^\/]*?\/(.*)$/.match(dst_file)
      if m && m.size == 3
        key_l1 = m[1].gsub('-', '_')
        if conf[key_l1].nil?
          puts "Filtered #{m[1]} - #{m[2]} - #{dst_file}"
          next
        end
      end

      # Keep redis conf files always readable
      if !OS.mac?
        m =  /.*(redis)\/(.*)$/.match(dst_file)
        if m
          safesudo("chmod +r #{dst_file}")
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

      # Now expand the template
      file_contents = expand_template(template)

      m = /.*(nginx-broker|nginx-epaper)[^\/]*?\/conf.d\/(.*)\.conf$/.match(dst_file)
      if m && m.size == 3
        # override destination path
        nginx_name  = m[1].gsub('-', '_')
        module_name = m[2].gsub('-', '_')
        if conf[nginx_name] && conf[nginx_name]['nginx'] && conf[nginx_name]['nginx']['alt_conf_dir_per_module']
          alt_conf_dir_per_module = conf[nginx_name]['nginx']['alt_conf_dir_per_module'][module_name]
          if alt_conf_dir_per_module
            dst_file = "#{@config.prefix}#{alt_conf_dir_per_module}/#{File.basename(dst_file)}"
          end
        end


        # included locations
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
          diff_and_write(contents: expand_template(template),
                         path: dst_file,
                         diff: diff_before_copy,
                         dry_run: dry_run
          )
        end
      end
    end
  end

  #
  templates_fallback_dir = File.expand_path(File.join(File.dirname(__FILE__), '../../../../', 'jobs'))

  #
  # Configure JOBS
  #
  if action == 'dry-run' || action == 'overwrite'
    puts "Configuring JOBS"
    @config.jobs.to_h.each do |name, job|
      @job_name        = name
      @job_description = @job_name
      @job_dir         = "#{@config.paths.working_directory}/jobs/#{@job_name}"
      @job_args        = ''
      @job_exec        = @config.bundle_exec || "#{%x[which rvm].strip} default"
      @job_working_dir = @config.paths.working_directory
      @job_environment = nil
      @job_threads     = nil
      @unified_config  = false

      if job
        @unified_config = job.unified || false

        if job.args
          job.args.to_h.each do | k, v |
            @job_args += "-#{k} #{v}"
          end
        end
        if job.exec_prefix
          @job_exec = job.exec_prefix
        end
        if job.working_directory_suffix
          @job_working_dir += "/#{job.working_directory_suffix}"
        end
        if job.environment
          @job_environment = "#{job.environment}"
        end
        @job_threads = job.threads

        if @unified_config
          @job_args += "-c #{@config.prefix}/etc/jobs/main.conf.json"
        end
      end
      puts "  #{name}:"
      if File.exists?("#{@job_dir}/conf.json.erb") && !@unified_config
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

      create_directory "#{@config.prefix}/etc/jobs"
      if @unified_config
        diff_and_write(contents: expand_template(template, pretty_json: true),
                       path: "#{@config.prefix}/etc/jobs/main.conf.json",
                       diff: diff_before_copy,
                       dry_run: dry_run
        )
      else
        diff_and_write(contents: expand_template(template, pretty_json: true),
                       path: "#{@config.prefix}/etc/jobs/#{@job_name}.conf.json",
                       diff: diff_before_copy,
                       dry_run: dry_run
        )
      end

      if File.exists? "#{@job_dir}/service.erb"
        template = "#{@job_dir}/service.erb"
      else
        template = "#{@config.paths.working_directory}/jobs/default.service.erb"
      end
      unless File.exists? template
        # last attempt - try sp-job/job/default.service.erb
        template = "#{templates_fallback_dir}/default.service.erb"
        if ! File.exists? template
          throw "Missing service file for #{@job_name} ( #{template} )"
        end
      end

      diff_and_write(contents: expand_template(template),
                     path: "#{@config.prefix}/lib/systemd/system/#{@job_name}@.service",
                     diff: diff_before_copy,
                     dry_run: dry_run
      )

      # logrotate.erb?
      if File.exists? "#{@job_dir}/logrorate.erb"
        template = "#{@job_dir}/logrotate.erb"
      else
        template = "#{@config.paths.working_directory}/jobs/default.logrotate.erb"
        if ! File.exists? template
          # last attempt - try sp-job/job/default.service.erb
          template = "#{templates_fallback_dir}/default.logrotate.erb"
        end
      end
      if File.exists? template
        diff_and_write(contents: expand_template(template),
                       path: "#{@config.prefix}/etc/logrotate.d/#{@job_name}",
                       diff: diff_before_copy,
                       dry_run: dry_run
        )
      end

    end
  end


end
