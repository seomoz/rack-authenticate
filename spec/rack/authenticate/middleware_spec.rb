require 'timecop'
require 'rack/authenticate/middleware'
require 'rack/authenticate/client'
require 'rack/test'

RSpec.configure do |c|
  c.treat_symbols_as_metadata_keys_with_true_values = true
  c.filter_run :f
  c.run_all_when_everything_filtered = true
end

class Integer
  def minutes
    self * 60
  end
end

module Rack
  module Authenticate
    class Middleware
      shared_context 'http_date' do
        let(:http_date) { "Tue, 15 Nov 1994 08:12:31 GMT" }
        let(:base_time) { Time.httpdate(http_date) }
        around(:each) do |example|
          if example.metadata[:no_timecop]
            example.run
          else
            Timecop.travel(base_time, &example)
          end
        end
      end

      describe Auth do
        include_context 'http_date'
        let(:content_md5) { 'some-long-md5' }
        let(:basic_env) do {
          "HTTP_HOST"       => "example.org",
          "SERVER_NAME"     => "example.org",
          "CONTENT_LENGTH"  => "0",
          "rack.url_scheme" => "http",
          "HTTPS"           => "off",
          "PATH_INFO"       => "/foo/bar",
          "SERVER_PORT"     => "80",
          "REQUEST_METHOD"  => "GET",
          "QUERY_STRING"    => "",
          "HTTP_DATE"       => http_date,
          "rack.input"      => StringIO.new("")
        } end

        describe "#basic?" do
          it 'returns true if given a basic auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'BASIC abc:asfkj23asdfkj'
            Auth.new(basic_env).should be_basic
          end

          it 'returns false if given an hmac auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'HMAC abc:asfkj23asdfkj'
            Auth.new(basic_env).should_not be_basic
          end
        end

        describe "#hmac?" do
          it 'returns true if given an hmac auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'HMAC abc:asfkj23asdfkj'
            Auth.new(basic_env).should be_hmac
          end

          it 'returns false if given a basic auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'BASIC abc:asfkj23asdfkj'
            Auth.new(basic_env).should_not be_hmac
          end
        end

        describe "#canonicalized_request" do
          it 'combines the HTTP verb, the date and the Request URI' do
            Auth.new(basic_env).canonicalized_request.split("\n").should eq([
              'GET',
              'http://example.org/foo/bar',
              http_date
            ])
          end

          it 'does not blow up if there is no date' do
            basic_env.delete('HTTP_DATE')
            Auth.new(basic_env).canonicalized_request
          end

          it 'includes the content MD5 when it is present' do
            basic_env['CONTENT_LENGTH'] = '10'
            basic_env['HTTP_CONTENT_MD5'] = content_md5

            Auth.new(basic_env).canonicalized_request.split("\n").should eq([
              'GET',
              'http://example.org/foo/bar',
              http_date,
              content_md5
            ])
          end
        end

        describe "#valid_current_date?" do
          it 'returns false if the date is not in the correct format' do
            basic_env['HTTP_DATE'] = 'some time yesterday'
            auth = Auth.new(basic_env, stub(:timestamp_minute_tolerance => 10))
            auth.should_not be_valid_current_date
          end

          it 'returns false if the date is outside the configured tolerance' do
            auth = Auth.new(basic_env, stub(:timestamp_minute_tolerance => 10))
            auth.should be_valid_current_date

            Timecop.freeze(base_time - 11.minutes) do
              auth.should_not be_valid_current_date
            end

            Timecop.freeze(base_time + 11.minutes) do
              auth.should_not be_valid_current_date
            end
          end

          it 'uses the X-Authorization-Date header if given in order to support browser AJAX requests' do
            basic_env['HTTP_DATE'] = (Time.now - 40.minutes).httpdate
            basic_env['HTTP_X_AUTHORIZATION_DATE'] = Time.now.httpdate
            auth = Auth.new(basic_env, stub(:timestamp_minute_tolerance => 10))
            auth.should be_valid_current_date

            Timecop.freeze(base_time - 11.minutes) do
              auth.should_not be_valid_current_date
            end

            Timecop.freeze(base_time + 11.minutes) do
              auth.should_not be_valid_current_date
            end
          end
        end

        describe "#has_all_required_parts?" do
          subject { Auth.new(env) }

          context 'for a request with no body' do
            let(:env) { basic_env }

            it 'returns true if it has everything it needs' do
              should have_all_required_parts
            end

            it 'returns false if it lacks the Date header' do
              basic_env.delete('HTTP_DATE')
              should_not have_all_required_parts
            end
          end

          context 'for a request with a body' do
            let(:env) { basic_env.merge('CONTENT_LENGTH' => '10') }

            it 'returns true if it has a content MD5' do
              basic_env['HTTP_CONTENT_MD5'] = content_md5
              should have_all_required_parts
            end

            it 'returns false if it lacks the content md5 header' do
              should_not have_all_required_parts
            end
          end
        end

        describe "#access_id" do
          it 'extracts it from the Auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'HMAC abc:asfkj23asdfkj'
            Auth.new(basic_env).access_id.should eq('abc')
          end
        end

        describe "#secret_key" do
          it 'finds the key matching the given access id from the configured creds' do
            basic_env['HTTP_AUTHORIZATION'] = 'HMAC abc:asfkj23asdfkj'
            configuration = Configuration.new
            configuration.hmac_secret_key do |access_id|
              { 'def' => '123456', 'abc' => '654321' }[access_id]
            end
            auth = Auth.new(basic_env, configuration)
            auth.secret_key.should eq('654321')
          end
        end

        describe "#given_digest" do
          it 'extracts it from the Auth header' do
            basic_env['HTTP_AUTHORIZATION'] = 'HMAC abc:asfkj23asdfkj'
            Auth.new(basic_env).given_digest.should eq('asfkj23asdfkj')
          end
        end

        describe "#calculated_digest" do
          it 'calculates the digest using the secret key, the canonicalized request and HMAC-SHA1' do
            digest = 'e593edc35cc753591052923c39ce6981330a4f13'
            HMAC::SHA1.hexdigest('the-key', 'canonicalized-request').should eq(digest)
            auth = Auth.new(basic_env)
            auth.stub(:secret_key => 'the-key', :canonicalized_request => 'canonicalized-request')
            auth.calculated_digest.should eq(digest)
          end
        end

        describe "#valid?" do
          let(:configuration) do
            Configuration.new.tap do |c|
              c.timestamp_minute_tolerance = 10
              c.hmac_secret_key { |id| { 'abc' => '123' }[id] }
            end
          end

          let(:access_id)     { 'abc' }
          let(:digest)        { '2baf72a8a52e1cfec37f588c5b4e0914cb4f63b5' }
          let(:env)           { basic_env.merge('HTTP_AUTHORIZATION' => "HMAC #{access_id}:#{digest}") }
          let(:auth)          { Auth.new(env, configuration) }

          it 'returns true if the calculated digest matches the given digest' do
            auth.should be_valid
          end

          it 'returns false if the digests do not match' do
            digest.gsub!('7', '6')
            auth.should_not be_valid
          end

          it 'returns false if no secret key can be found for the given access id' do
            access_id.gsub!('a', '1')
            auth.should_not be_valid
          end

          it 'returns false if there is no given credential' do
            env.delete('HTTP_AUTHORIZATION')
            auth.should_not be_valid
          end

          it 'returns false if the date is not in a valid range' do
            Timecop.freeze(base_time + 12.minutes) do
              auth.should_not be_valid
            end
          end
        end
      end

      describe self do
        include_context 'http_date'
        include Rack::Test::Methods

        let(:hmac_auth_creds) do {
          'abc' => '123',
          'def' => '456'
        } end

        let(:basic_auth_creds) do {
          'abc' => 'foo',
          'def' => 'bar'
        } end

        def basis_auth_value(username, password)
          ["#{username}:#{password}"].pack("m*")
        end

        def configure(&block)
          @configuration_block = block
        end

        let(:app) do
          hmac_creds = hmac_auth_creds
          basic_creds = basic_auth_creds
          config_block = @configuration_block || Proc.new { }

          Rack::Builder.new do
            use Rack::ContentLength
            use Rack::Authenticate::Middleware do |config|
              config.hmac_secret_key { |access_id| hmac_creds[access_id] }
              config.basic_auth_validation { |u, p| basic_creds[u] == p }
              config.timestamp_minute_tolerance = 30
              config_block.call(config)
            end

            run lambda { |env| [200, {}, ['OK']] }
          end
        end

        it 'responds with a 401 if there are no headers at all' do
          get '/'
          last_response.status.should eq(401)
        end

        it 'responds with a 400 when the request is missing required information for HMAC authorization' do
          # no date header set...
          header 'Authorization', 'HMAC abc:adfafdsfdas'
          get '/'
          last_response.status.should eq(400)
        end

        it 'responds with a 400 when given an unrecognized type of authorization' do
          header 'Date', "Tue, 15 Nov 1994 08:12:31 GMT"
          header 'Authorization', 'DIGEST abc:adfafdsfdas'
          get '/'
          last_response.status.should eq(400)
        end

        it 'responds with a 401 when there is no authorization header' do
          header 'Date', "Tue, 15 Nov 1994 08:12:31 GMT"
          get '/'
          last_response.status.should eq(401)
        end

        it 'responds with a 401 when there is an HMAC authorization header but it is invalid' do
          header 'Authorization', 'HMAC abc:asfkj23asdfkj'
          header 'Date', "Tue, 15 Nov 1994 08:12:31 GMT"
          get '/'
          last_response.status.should eq(401)
        end

        it 'lets the request through when there is a valid HMAC authorization header' do
          header 'Authorization', 'HMAC abc:34a70d9901bd447a02157f9fc598e43d6bf5b484'
          header 'Date', http_date
          get '/'
          last_response.status.should eq(200)
        end

        it 'allows an HMAC-authorized request to use the custom X-Authorization-Date header to handle browers that cannot override a Date header on an AJAX request' do
          header 'Authorization', 'HMAC abc:34a70d9901bd447a02157f9fc598e43d6bf5b484'
          header 'X-Authorization-Date', http_date
          get '/'
          last_response.status.should eq(200)
        end

        it 'lets the request through when there is a valid Basic authorization header' do
          header 'Authorization', "BASIC #{basis_auth_value('abc', 'foo')}"
          get '/'
          last_response.status.should eq(200)
        end

        it 'responds with a 401 when there is a BASIC authorization header but it is invalid' do
          header 'Authorization', "BASIC #{basis_auth_value('abc', 'foot')}"
          get '/'
          last_response.status.should eq(401)
        end

        it 'generates the same signature as the client', :no_timecop do
          client = Client.new('abc', hmac_auth_creds['abc'])
          client.request_signature_headers('post', 'http://example.org/foo', "some content").each do |key, value|
            header key, value
          end

          header 'Content-Type', 'text/plain'
          post '/foo', "some content"
          last_response.status.should eq(200)
        end

        it 'generates the same signature as an AJAX client', :no_timecop do
          client = Client.new('abc', hmac_auth_creds['abc'], :ajax => true)
          client.request_signature_headers('post', 'http://example.org/foo', "some content").each do |key, value|
            header key, value
          end

          header 'Content-Type', 'text/plain'
          post '/foo', "some content"
          last_response.status.should eq(200)
        end

        context 'when cross origin resource sharing is supported' do
          before { configure { |c| c.support_cross_origin_resource_sharing = true } }
          let(:headers) { 'X-Authorization-Date, Content-MD5, Authorization, Content-Type' }
          let(:origin)  { 'http://foo.example.com' }

          let(:expected_response_headers) do {
            'Content-Type'                     => 'text/plain',
            'Access-Control-Allow-Origin'      => origin,
            'Access-Control-Allow-Methods'     => 'PUT',
            'Access-Control-Allow-Credentials' => 'true',
            'Access-Control-Max-Age'           => ACCESS_CONTROL_MAX_AGE.to_s
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

        context 'when cross origin resource sharing is not supported' do
          before { configure { |c| c.support_cross_origin_resource_sharing = false } }

          it 'does not respond to a CORS OPTIONS request' do
            header 'Origin', 'http://foo.example.com'
            header 'Access-Control-Request-Method', 'PUT'
            options '/'

            last_response.status.should eq(401)
            last_response.headers.keys.select { |k| k.include?('Access-Control') }.should eq([])
          end

          it 'does not append the Access-Control-Allow-Origin header to every response' do
            header 'Origin', 'http://foo.example.com'
            get '/'
            last_response.headers.keys.should_not include('Access-Control-Allow-Origin')
          end
        end
      end
    end
  end
end

