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
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_dependency "concurrent-ruby"
  spec.add_dependency "os"
  spec.add_dependency "sp-duh", ">= 0.2.5"
  spec.add_dependency "redis"
  spec.add_dependency "beaneater"
  spec.add_dependency "pg"
  spec.add_dependency "oauth2"
  spec.add_dependency "oauth2-client"
  spec.add_dependency "curb"
  spec.add_dependency "rails"

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
