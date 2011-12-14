require 'timecop'
require 'rack/authenticate/middleware'
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
        around(:each) { |e| Timecop.travel(base_time, &e) }
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

          it 'includes the content MD5 and Type when they are present' do
            basic_env['CONTENT_LENGTH'] = '10'
            basic_env['HTTP_CONTENT_MD5'] = content_md5
            basic_env['CONTENT_TYPE'] = 'text/plain'

            Auth.new(basic_env).canonicalized_request.split("\n").should eq([
              'GET',
              'http://example.org/foo/bar',
              http_date,
              'text/plain',
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

            it 'returns true if it has a content type and content MD5' do
              basic_env['HTTP_CONTENT_MD5'] = content_md5
              basic_env['CONTENT_TYPE'] = 'text/plain'
              should have_all_required_parts
            end

            it 'returns false if it lacks the content md5 header' do
              basic_env['CONTENT_TYPE'] = 'text/plain'
              should_not have_all_required_parts
            end

            it 'returns false if it lacks the content type header' do
              basic_env['HTTP_CONTENT_MD5'] = content_md5
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
            auth = Auth.new(basic_env, stub(:hmac_creds => { 'def' => '123456', 'abc' => '654321' }))
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
          let(:configuration) { stub(:hmac_creds => { 'abc' => '123' }, :timestamp_minute_tolerance => 10) }
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

        let(:hmac_creds) do {
          'abc' => '123',
          'def' => '456'
        } end

        let(:app) do
          creds = hmac_creds
          Rack::Builder.new do
            use Rack::ContentLength
            use Rack::Authenticate::Middleware do |config|
              config.hmac_creds = creds
              config.timestamp_minute_tolerance = 30
            end

            run lambda { |env| [200, {}, ['OK']] }
          end
        end

        it 'responds with a 401 if there are no headers at all' do
          get '/'
          last_response.status.should eq(401)
        end

        it 'responds with a 400 when the request is missing required information' do
          # no date header set...
          header 'Authorization', 'HMAC abc:adfafdsfdas'
          get '/'
          last_response.status.should eq(400)
        end

        it 'responds with a 401 when there is no authorization header' do
          header 'Date', "Tue, 15 Nov 1994 08:12:31 GMT"
          get '/'
          last_response.status.should eq(401)
        end

        it 'responds with a 401 when there is an authorization header but it is invalid' do
          header 'Authorization', 'HMAC abc:asfkj23asdfkj'
          header 'Date', "Tue, 15 Nov 1994 08:12:31 GMT"
          get '/'
          last_response.status.should eq(401)
        end

        it 'lets the request through when there is a valid authorization header' do
          header 'Authorization', 'HMAC abc:34a70d9901bd447a02157f9fc598e43d6bf5b484'
          header 'Date', http_date
          get '/'
          last_response.status.should eq(200)
        end
      end
    end
  end
end
