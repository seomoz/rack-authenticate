module Rack
  module Authenticate
    class CORSMiddleware
      ACCESS_CONTROL_MAX_AGE = 60 * 60 * 48 # 48 hours

      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, body = if cors_preflight_request?(env)
          cors_allowances(env)
        else
          @app.call(env)
        end

        if env.has_key?('HTTP_ORIGIN')
          headers['Access-Control-Allow-Origin'] = env['HTTP_ORIGIN']
          headers['Access-Control-Allow-Credentials'] = 'true'
        end

        [status, headers, body]
      end

      def cors_preflight_request?(env)
        env['REQUEST_METHOD'] == 'OPTIONS' &&
        %w[ HTTP_ACCESS_CONTROL_REQUEST_METHOD HTTP_ORIGIN ].all? { |k| env.has_key?(k) }
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

