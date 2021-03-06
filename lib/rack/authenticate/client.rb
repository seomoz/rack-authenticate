require 'hmac-sha1'
require 'digest/md5'
require 'time'

module Rack
  module Authenticate
    class Client
      attr_reader :access_id, :secret_key
      def initialize(access_id, secret_key, options = {})
        @access_id, @secret_key = access_id, secret_key
        @ajax = options[:ajax]
      end

      def request_signature_headers(method, url, content = nil)
        {}.tap do |headers|
          headers[date_header_field] = date = Time.now.httpdate
          request = [method.to_s.upcase, url, date]

          if content
            content_md5 = Digest::MD5.hexdigest(content)
            headers['Content-MD5'] = content_md5
            request << content_md5
          end

          digest = HMAC::SHA1.hexdigest(secret_key, request.join("\n"))
          headers['Authorization'] = "HMAC #{access_id}:#{digest}"
        end
      end

    private

      def date_header_field
        # Browsers do not allow javascript to set the Date header when making an AJAX request:
        #   http://www.w3.org/TR/XMLHttpRequest/#the-setrequestheader-method
        # Thus, we allow the custom X-Authorization-Date header to be used instead of Date.
        @ajax ? 'X-Authorization-Date' : 'Date'
      end
    end
  end
end

