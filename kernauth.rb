require "json"
require "net/http"
require "uri"

def check_body(app_id, license_key)
  {
    "protocol_version" => 1,
    "public_app_id" => app_id,
    "client_version" => "1.0.0",
    "license_key" => license_key,
  }
end

def api_message(payload, fallback)
  message = payload.is_a?(Hash) ? payload.dig("error", "message") : nil
  message.is_a?(String) && !message.empty? ? message : fallback
end

class KernAuth
  attr_reader :message, :expires_at

  def initialize(api, app_id)
    @api = api
    @app_id = app_id
    @message = ""
    @expires_at = nil
  end

  def check(license_key)
    uri = URI("#{@api}/v1/client/check")
    response = Net::HTTP.post(uri, JSON.generate(check_body(@app_id, license_key)), "content-type" => "application/json")
    payload = JSON.parse(response.body)
    unless response.is_a?(Net::HTTPSuccess) && payload["valid"] == true
      @message = api_message(payload, "check failed (#{response.code})")
      @expires_at = nil
      return false
    end
    @message = "License is active"
    @expires_at = payload["expires_at"].is_a?(String) ? payload["expires_at"] : nil
    true
  rescue StandardError => error
    @message = error.message
    @expires_at = nil
    false
  end
end
