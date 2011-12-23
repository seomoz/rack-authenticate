require 'rack'
require 'hmac-sha1'
require 'time'

module Rack
  module Authenticate
    class Middleware < ::Rack::Auth::Basic
      ACCESS_CONTROL_MAX_AGE = 60 * 60 * 24 # 24 hours

      class Configuration
        def initialize(*args)
          self.timestamp_minute_tolerance ||= 30
          self.hmac_secret_key { |access_id| }
          self.basic_auth_validation { |u, p| false }
          self.support_cross_origin_resource_sharing = false
        end

        attr_accessor :timestamp_minute_tolerance
        attr_writer   :support_cross_origin_resource_sharing
        attr_reader   :basic_auth_validation_block

        def hmac_secret_key(&block)
          @hmac_secret_key_block = block
        end

        def hmac_secret_key_for(access_id)
          @hmac_secret_key_block[access_id]
        end

        def basic_auth_validation(&block)
          @basic_auth_validation_block = block
        end

        def support_cross_origin_resource_sharing?
          @support_cross_origin_resource_sharing
        end
      end

      class RequestBodyProxy
        def initialize(input, md5)
          @input, @md5 = input, md5
          @total_input, @eof = '', false
          @next_line, @next_byte = nil, ''
        end

        def gets
          return nil if eof?

          unless @next_line
            @next_line = @input.gets
            @total_input << @next_line
          end

          this_line, @next_line = @next_line, @input.gets
          @next_line ? @total_input << @next_line : eof!
          this_line
        end

        def read(*args)
          if eof?
            ''
          elsif args.none?
            @total_input = @input.read(*args)
            eof!
            @total_input
          elsif args.size == 1 # length
            length = args.first
            bytes_to_read = @next_byte.size.zero? ? length : length + 1
            section = @input.read(bytes_to_read)
            (@next_byte + section[0..-2]).tap do |string|
              @next_byte = section[-1]
              @total_input << string
            end
          else # length, buffer
            @input.read(*args)
          end
        end

        def each
          while line = gets
            yield line
          end
        end

      private

        def eof?
          @eof
        end

        def eof!
          @eof = true
          throw :invalid_content_md5 unless @md5 == Digest::MD5.hexdigest(@total_input)
        end
      end

      class Auth < ::Rack::Auth::AbstractRequest
        def initialize(env, configuration = Configuration.new)
          super(env)
          @configuration = configuration
        end

        def basic?
          :basic == scheme
        end

        def hmac?
          :hmac == scheme
        end

        def has_all_required_parts?
          return false unless date

          if has_content?
            content_md5.to_s != ''
          else
            true
          end
        end

        def request
          @request ||= ::Rack::Request.new(@env)
        end unless method_defined?(:request)

        def valid_current_date?
          timestamp = Time.httpdate(date)
        rescue ArgumentError
          return false
        else
          tolerance = @configuration.timestamp_minute_tolerance * 60
          now = Time.now
          (now - tolerance) <= timestamp && (now + tolerance) >= timestamp
        end

        def has_content?
          request.content_length.to_i > 0
        end

        # TODO: replace the request body with a proxy object that verifies this when it is read.
        def content_md5
          request.env['HTTP_CONTENT_MD5']
        end

        def canonicalized_request
          parts = [ request.request_method, request.url, date ]
          parts << content_md5 if has_content?
          parts.join("\n")
        end

        def access_id
          @access_id ||= params.split(':').first
        end

        def secret_key
          @configuration.hmac_secret_key_for(access_id)
        end

        def given_digest
          @given_digest ||= params.split(':').last
        end

        def calculated_digest
          @calculated_digest ||= HMAC::SHA1.hexdigest(secret_key, canonicalized_request)
        end

        def valid?
          provided? &&
          secret_key &&
          valid_current_date? &&
          calculated_digest == given_digest
        end

        def supported_cors_preflight_request?
          @configuration.support_cross_origin_resource_sharing? &&
          request.request_method == 'OPTIONS' &&
          %w[ HTTP_ACCESS_CONTROL_REQUEST_METHOD HTTP_ORIGIN ].all? { |k| request.env.has_key?(k) }
        end

      private

        def date
          @date ||= request.env[date_header_field]
        end

        def date_header_field
          # Browsers do not allow javascript to set the Date header when making an AJAX request:
          #   http://www.w3.org/TR/XMLHttpRequest/#the-setrequestheader-method
          # Thus, we allow the custom X-Authorization-Date header to be used instead of Date.
          @date_header_field ||= ['HTTP_X_AUTHORIZATION_DATE', 'HTTP_DATE'].find { |k| request.env.has_key?(k) } || 'HTTP_DATE'
        end
      end

      def initialize(app)
        @configuration = Configuration.new
        yield @configuration
        super(app, &@configuration.basic_auth_validation_block)
      end

      def call(env)
        auth = Auth.new(env, @configuration)
        return cors_allowances(env) if auth.supported_cors_preflight_request?

        _call(env, auth) { super }.tap do |(status, headers, body)|
          if @configuration.support_cross_origin_resource_sharing? && env.has_key?('HTTP_ORIGIN')
            headers['Access-Control-Allow-Origin'] = env['HTTP_ORIGIN']
          end
        end
      end

    private

      def _call(env, auth)
        return unauthorized unless auth.provided?
        return yield            if auth.basic?
        return bad_request  unless auth.hmac?
        return bad_request  unless auth.has_all_required_parts?
        return unauthorized unless auth.valid?

        @app.call(env)
      end

      def cors_allowances(env)
        headers = {
          'Access-Control-Allow-Origin'      => env['HTTP_ORIGIN'],
          'Access-Control-Allow-Methods'     => env['HTTP_ACCESS_CONTROL_REQUEST_METHOD'],
          'Access-Control-Allow-Credentials' => 'true',
          'Access-Control-Max-Age'           => ACCESS_CONTROL_MAX_AGE.to_s,
          'Content-Type'                     => 'text/plain'
        }

        if env.has_key?('HTTP_ACCESS_CONTROL_REQUEST_HEADERS')
          headers['Access-Control-Allow-Headers'] = env['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']
        end

        [200, headers, []]
      end
    end
  end
end

