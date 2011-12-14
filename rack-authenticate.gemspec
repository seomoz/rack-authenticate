# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "rack/authenticate/version"

Gem::Specification.new do |s|
  s.name        = "rack-authenticate"
  s.version     = Rack::Authenticate::VERSION
  s.authors     = ["Myron Marston"]
  s.email       = ["myron.marston@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{A rack middleware that authenticates requests either using basic auth or via signed HMAC.}
  s.description = %q{A rack middleware that authenticates requests either using basic auth or via signed HMAC.}

  s.rubyforge_project = "rack-authenticate"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'ruby-hmac', '~> 0.4.0'
  s.add_development_dependency 'rspec', '~> 2.8.0.rc1'
  s.add_development_dependency 'rack-test', '~> 0.6.1'
  s.add_development_dependency 'timecop', '~> 0.3.5'
  s.add_development_dependency 'rake', '~> 0.9.2.2'
end
