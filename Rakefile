require "bundler/gem_tasks"
require "rspec/core/rake_task" unless RUBY_ENGINE == 'jruby'

if RUBY_ENGINE == 'jruby'

    require 'rake/javaextensiontask'

    ENV['JAVA_TOOL_OPTIONS']='-Dfile.encoding=UTF-8'
    ENV['JAVA_EXT_DIR']     = File.expand_path(File.join(File.dirname(__FILE__), 'jruby', 'ext'))
    ENV['JAVA_LIB_DIR']     = File.expand_path(File.join(File.dirname(__FILE__), 'jruby', 'lib'))

    spec = Gem::Specification.load('sp-job.gemspec')

    Rake::JavaExtensionTask.new('sp-job', spec) do |compile|
        jars = FileList['lib/java/*.jar']
        compile.ext_dir   = ENV['JAVA_EXT_DIR']
        compile.lib_dir   = ENV['JAVA_LIB_DIR']
        compile.classpath = jars.map { |x| File.expand_path x }.join ':'
    end

    desc 'Compile JAR'
    task :jar => [:clean, :'compile:sp-job'] do
        puts "Done"
    end
end


Dir.glob('lib/tasks/*.rake').each { |r| load r  }

unless RUBY_ENGINE == 'jruby'
    RSpec::Core::RakeTask.new(:spec)
    task :default => :spec
end
