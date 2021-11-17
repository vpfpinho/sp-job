# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'sp/job/version'

Gem::Specification.new do |spec|
  spec.name          = "sp-job"
  spec.version       = SP::Job::VERSION
  spec.authors       = ["Eurico Inocencio, Vitor Pinho"]
  spec.email         = ["eurico.inocencio@gmail.com, vitor.pinho@servicepartner.pt"]

  spec.summary       = %q{Common functionality for beanstalk jobs}
  spec.description   = %q{Base classes for your own jobs and open sourced generic utility jobs}
  spec.homepage      = "https://github.com/vpfpinho/sp-job"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'bin'
  spec.executables   = ['queue-job', 'unique-file', 'configure']
  spec.require_paths = ['lib']
  spec.add_dependency 'os'
  spec.add_dependency 'ffi'
  spec.add_dependency 'redis'
  spec.add_dependency 'backburner'
  spec.add_dependency 'pg'            unless RUBY_ENGINE == 'jruby'
  spec.add_dependency 'jruby-pg'      if     RUBY_ENGINE == 'jruby'
  spec.add_dependency 'manticore'     if     RUBY_ENGINE == 'jruby'
  spec.add_dependency 'curb'          unless RUBY_ENGINE == 'jruby'
  spec.add_dependency 'oauth2'        unless RUBY_ENGINE == 'jruby'
  spec.add_dependency 'oauth2-client' unless RUBY_ENGINE == 'jruby'
  spec.add_dependency 'mail'
  spec.add_dependency 'json'
  spec.add_dependency 'jwt'
  spec.add_dependency 'awesome_print'
  spec.add_dependency 'rollbar'
  spec.add_dependency 'roadie'

  spec.add_development_dependency 'ruby-debug' if     RUBY_ENGINE == 'jruby'
  spec.add_development_dependency 'byebug'     unless RUBY_ENGINE == 'jruby'
  spec.add_development_dependency 'bundler', '~> 1.14'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
