require 'rack/authenticate/cors_middleware'
require 'rack/test'

RSpec.configure do |c|
  c.treat_symbols_as_metadata_keys_with_true_values = true
  c.filter_run :f
  c.run_all_when_everything_filtered = true
end

module Rack
  module Authenticate
    describe CORSMiddleware do
      include Rack::Test::Methods

      let(:app) do
        Rack::Builder.new do
          use Rack::ContentLength
          use Rack::Authenticate::CORSMiddleware
          run lambda { |env| [200, {}, ['OK']] }
        end
      end

      let(:headers) { 'X-Authorization-Date, Content-MD5, Authorization, Content-Type' }
      let(:origin)  { 'http://foo.example.com' }

      let(:expected_response_headers) do {
        'Content-Type'                     => 'text/plain',
        'Access-Control-Allow-Origin'      => origin,
        'Access-Control-Allow-Methods'     => 'PUT',
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Max-Age'           => CORSMiddleware::ACCESS_CONTROL_MAX_AGE.to_s
      } end

      it 'responds to a CORS OPTIONS request with all of the correct headers' do
        header 'Origin', origin
        header 'Access-Control-Request-Method', 'PUT'
        options '/'

        last_response.status.should eq(200)
        last_response.headers.should include(expected_response_headers)
        last_response.headers.should_not have_key('Access-Control-Allow-Headers')
      end

      it 'includes Access-Control-Allow-Headers when they the request asks about them' do
        header 'Origin', origin
        header 'Access-Control-Request-Method', 'PUT'
        header 'Access-Control-Request-Headers', headers
        options '/'

        last_response.status.should eq(200)
        last_response.headers.should include(expected_response_headers.merge(
          'Access-Control-Allow-Headers' => headers
        ))
      end

      it 'appends the Access-Control-Allow-Origin header to every response to a request with an Origin header' do
        header 'Origin', origin
        get '/'
        last_response.headers.should include('Access-Control-Allow-Origin' => origin)
      end

      it 'does not append a Access-Control-Allow-Origin header to a request without an Origin header' do
        get '/'
        last_response.headers.keys.should_not include('Access-Control-Allow-Origin')
      end
    end
  end
end

