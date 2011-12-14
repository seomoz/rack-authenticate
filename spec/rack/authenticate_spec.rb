require 'rack/authenticate'

RSpec.configure do |c|
  c.treat_symbols_as_metadata_keys_with_true_values = true
  c.filter_run :f
  c.run_all_when_everything_filtered = true
end

module Rack
  describe Authenticate do
    describe "#new_secret_key" do
      it "generates a long random string" do
        Rack::Authenticate.new_secret_key.should match(/[A-Za-z0-9\\\/\+]{60,}/)
      end
    end
  end
end
