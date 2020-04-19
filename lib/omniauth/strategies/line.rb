require 'jwt'
require 'omniauth-oauth2'
require 'json'
require 'uri'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2

      ALLOWED_ISSUERS = ['access.line.me', 'https://access.line.me'].freeze

      option :name, 'line'
      option :scope, 'profile'
      option :skip_jwt, false
      option :jwt_leeway, 60

      option :token_params, {
        grant_type: 'authorization_code'
      }

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      uid { raw_info['userId'] }

      info do
        hash = {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage']
        }

        hash[:id_token] = access_token['id_token']
        if !options[:skip_jwt] && !access_token['id_token'].nil?
          decoded = ::JWT.decode(access_token['id_token'], options.client_secret, false).first

          # We have to manually verify the claims because the third parameter to
          # JWT.decode is false since no verification key is provided.
          ::JWT::Verify.verify_claims(decoded,
                                      verify_iss: true,
                                      iss: ALLOWED_ISSUERS,
                                      verify_aud: true,
                                      aud: options.client_id,
                                      verify_sub: false,
                                      verify_expiration: true,
                                      verify_not_before: true,
                                      verify_iat: true,
                                      verify_jti: false,
                                      leeway: options[:jwt_leeway])

          hash[:id_info] = decoded
          hash[:email] = decoded["email"]
        end
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get('v2/profile').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def build_access_token
        verifier = request.params["code"]
        get_token_params = {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true))
        result = client.auth_code.get_token(verifier, get_token_params, deep_symbolize(options.auth_token_params))
        return result
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

    end
  end
end
