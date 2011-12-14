require 'rack'
require 'hmac-sha1'
require 'time'

module Rack
  module Authenticate
    class Middleware < ::Rack::Auth::AbstractHandler
      class Configuration < Struct.new(:hmac_creds, :timestamp_minute_tolerance)
        def initialize(*args)
          super
          self.hmac_creds ||= {}
          self.timestamp_minute_tolerance ||= 30
        end
      end

      # TODO: support basic auth
      class Auth < ::Rack::Auth::AbstractRequest
        def initialize(env, configuration = Configuration.new)
          super(env)
          @configuration = configuration
        end

        def has_all_required_parts?
          return false unless date

          if has_content?
            content_md5.to_s != '' && request.content_type.to_s != ''
          else
            true
          end
        end

        def date
          request.env['HTTP_DATE']
        end

        def valid_current_date?
          timestamp = Time.httpdate(date)
        rescue ArgumentError
          return false
        else
          tolerance = @configuration.timestamp_minute_tolerance * 60
          now = Time.now
          range = (now - tolerance)..(now + tolerance)
          return range.include?(timestamp)
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
          parts += [ request.content_type, content_md5 ] if has_content?
          parts.join("\n")
        end

        def access_id
          @access_id ||= params.split(':').first
        end

        def secret_key
          @configuration.hmac_creds[access_id]
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
      end

      def initialize(app)
        super
        @configuration = Configuration.new
        yield @configuration
      end

      def call(env)
        auth = Auth.new(env, @configuration)
        return unauthorized unless auth.provided?
        return bad_request  unless auth.has_all_required_parts?
        return unauthorized unless auth.valid?
        @app.call(env)
      end

    private

      def challenge
        'HMAC realm="%s"' % realm
      end
    end
  end
end

