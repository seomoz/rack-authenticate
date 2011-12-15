require 'rack/authenticate/client'
require 'timecop'

RSpec.configure do |c|
  c.treat_symbols_as_metadata_keys_with_true_values = true
  c.filter_run :f
  c.run_all_when_everything_filtered = true
end

module Rack
  module Authenticate
    describe Client do
      let(:http_date) { "Tue, 15 Nov 1994 08:12:31 GMT" }
      let(:base_time) { Time.httpdate(http_date) }
      around(:each) { |e| Timecop.travel(base_time, &e) }

      let(:access_id)  { 'my-access-id' }
      let(:secret_key) { 'the-s3cr3t' }
      let(:options)    { {} }
      subject { Client.new(access_id, secret_key, options) }

      describe "#request_signature_headers" do
        it 'raises an Argument error if given a content type but not content' do
          expect {
            subject.request_signature_headers("get", "http://foo.com/", "text/plain", nil)
          }.to raise_error(ArgumentError)
        end

        it 'raises an Argument error if given a content but no content type' do
          expect {
            subject.request_signature_headers("get", "http://foo.com/", nil, "content")
          }.to raise_error(ArgumentError)
        end

        it 'returns the auth header using the HMAC digest' do
          HMAC::SHA1.stub(:hexdigest => 'the-hex-digest')
          headers = subject.request_signature_headers("get", "http://foo.com/")
          headers.should include('Authorization' => "HMAC my-access-id:the-hex-digest")
        end

        it 'uses the secret key to generate the digest' do
          HMAC::SHA1.should_receive(:hexdigest).with(secret_key, anything)
          subject.request_signature_headers("get", "http://foo.com/")
        end

        it 'uses the uppercased request method in the digest' do
          HMAC::SHA1.should_receive(:hexdigest) do |key, request|
            request.split("\n").first.should eq("GET")
          end

          subject.request_signature_headers("get", "http://foo.com/")
        end

        it 'handles symbol methods' do
          HMAC::SHA1.should_receive(:hexdigest) do |key, request|
            request.split("\n").first.should eq("DELETE")
          end

          subject.request_signature_headers(:delete, "http://foo.com/")
        end

        it 'uses the request URL in the digest' do
          HMAC::SHA1.should_receive(:hexdigest) do |key, request|
            request.split("\n")[1].should eq("http://foo.com/bar?q=buzz")
          end

          subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
        end

        it 'uses the current http date in the digest' do
          HMAC::SHA1.should_receive(:hexdigest) do |key, request|
            request.split("\n")[2].should eq(http_date)
          end
          subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
        end

        it 'returns the http date in the headers hash' do
          headers = subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
          headers.should include('Date' => http_date)
        end

        it 'returns the http date as the X-Authorization-Date in the headers hash for an ajax client' do
          options[:ajax] = true
          headers = subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
          headers.keys.should_not include('Date')
          headers.should include('X-Authorization-Date' => http_date)
        end

        context 'when there is no content' do
          it 'does not use anything beyond the method, url and date for the digest' do
            HMAC::SHA1.should_receive(:hexdigest) do |key, request|
              request.split("\n").should have(3).parts
            end

            subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
          end

          it 'does not include a Content-MD5 header in the headers hash' do
            headers = subject.request_signature_headers("get", "http://foo.com/bar?q=buzz")
            headers.should_not have_key('Content-MD5')
          end
        end

        context 'when there is content' do
          let(:content_md5) { 'the-content-md5' }
          before(:each) do
            Digest::MD5.stub(:hexdigest).and_return(content_md5)
          end

          it 'returns the Content-MD5 header in the headers hash' do
            headers = subject.request_signature_headers("get", "http://foo.com/bar?q=buzz", "text/plain", "content")
            headers.should include('Content-MD5' => content_md5)
          end

          it 'generates the Content-MD5 based on the content' do
            Digest::MD5.should_receive(:hexdigest).with("content")
            subject.request_signature_headers("get", "http://foo.com/bar?q=buzz", "text/plain", "content")
          end

          it 'uses the content type and content md5 in the digest' do
            HMAC::SHA1.should_receive(:hexdigest) do |key, request|
              parts = request.split("\n")
              parts.should have(5).parts
              parts.last(2).should eq(['text/plain', 'the-content-md5'])
            end

            subject.request_signature_headers("get", "http://foo.com/bar?q=buzz", "text/plain", "content")
          end
        end
      end
    end
  end
end

