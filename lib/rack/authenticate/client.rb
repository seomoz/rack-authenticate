require 'hmac-sha1'
require 'digest/md5'
require 'time'

module Rack
  module Authenticate
    class Client
      attr_reader :access_id, :secret_key
      def initialize(access_id, secret_key)
        @access_id, @secret_key = access_id, secret_key
      end

      def request_signature_headers(method, url, content_type = nil, content = nil)
        {}.tap do |headers|
          headers['Date'] = date = Time.now.httpdate
          request = [method.to_s.upcase, url, date]

          if content_md5 = content_md5_for(content_type, content)
            headers['Content-MD5'] = content_md5
            request += [content_type, content_md5]
          end

          digest = HMAC::SHA1.hexdigest(secret_key, request.join("\n"))
          headers['Authorization'] = "HMAC #{access_id}:#{digest}"
        end
      end

    private

      def content_md5_for(content_type, content)
        if content_type.nil? && content.nil?
          # no-op
        elsif content_type && content
          Digest::MD5.hexdigest(content)
        else
          raise ArgumentError.new("Both content_type and content must be given or neither.")
        end
      end
    end
  end
end

