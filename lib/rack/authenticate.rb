module Rack
  module Authenticate
    def self.new_secret_key
      require 'base64'
      require 'securerandom'
      require 'digest/sha2'
      Base64.encode64(Digest::SHA2.new(512).digest(SecureRandom.random_bytes(512))).chomp
    end
  end
end

