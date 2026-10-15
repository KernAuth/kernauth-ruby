# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "time"
require "uri"

API = "https://api.kernauth.com"
APP_ID = "__PUBLIC_APP_ID__"
PUBLIC_KEY = "__PUBLIC_KEY__"
FIELDS = %w[protocol_version entitlement_id application_id license_id status features device_id issued_at expires_at server_time nonce key_id].freeze

class KernAuth
  attr_reader :api, :app_id, :public_key, :message, :entitlement
  attr_accessor :success

  def initialize(api = API, app_id = APP_ID, public_key = PUBLIC_KEY)
    @api = api
    @app_id = app_id
    @public_key = public_key
    @success = false
    @message = ""
    @entitlement = nil
  end

  def validate(license_key, installation_id)
    call("validate", license_key, installation_id, "License is active")
  end

  def call(mode, license_key, installation_id, ok_message)
    @entitlement = request(mode, license_key, installation_id, api, app_id, public_key)
    @entitlement["features"] = canonical_features(@entitlement["features"])
    self.success = true
    @message = ok_message
    true
  rescue StandardError => error
    self.success = false
    @message = error.message
    @entitlement = nil
    false
  end
end

def canonical(entitlement)
  lines = FIELDS.map do |name|
    value = name == "features" ? canonical_features(entitlement["features"]) : entitlement[name].to_s
    raise "Invalid entitlement field" if value.include?("\n") || value.include?("\r")

    "#{name}=#{value}"
  end
  "#{lines.join("\n")}\n"
end

def canonical_features(value)
  value = JSON.parse(value) if value.is_a?(String)
  encode_json(sort_json(value))
end

def sort_json(value)
  case value
  when Hash
    value.keys.map(&:to_s).sort.to_h { |key| [key, sort_json(value[key] || value[key.to_sym])] }
  when Array
    value.map { |item| sort_json(item) }
  else
    value
  end
end

def encode_json(value)
  case value
  when Hash
    "{#{value.map { |key, item| "#{encode_json(key)}:#{encode_json(item)}" }.join(",")}}"
  when Array
    "[#{value.map { |item| encode_json(item) }.join(",")}]"
  when String
    JSON.generate(value)
  when Integer
    value.to_s
  when TrueClass, FalseClass
    value.to_s
  when NilClass
    "null"
  else
    raise "Invalid features"
  end
end

def strict_b64(value)
  return nil unless value.is_a?(String) && value.match?(/\A[A-Za-z0-9+\/]+={0,2}\z/) && (value.length % 4).zero?

  Base64.strict_decode64(value)
rescue ArgumentError
  nil
end

def verify_grant(grant, nonce, app_id = APP_ID, public_key = PUBLIC_KEY, now = Time.now)
  ent = grant["entitlement"]
  expiry = Time.iso8601(ent["expires_at"])
  return false unless ent["protocol_version"] == 1 && ent["nonce"] == nonce &&
                       ent["application_id"] == app_id &&
                       ent["status"] == "active" && expiry > now

  raw = strict_b64(public_key)
  signature = strict_b64(grant["signature"])
  return false if raw.nil? || raw.bytesize != 32 || signature.nil? || signature.bytesize != 64

  key = OpenSSL::PKey.new_raw_public_key("ED25519", raw)
  key.verify(nil, signature, canonical(ent))
rescue OpenSSL::PKey::PKeyError, ArgumentError, JSON::ParserError
  false
end

def api_message(raw, fallback)
  payload = JSON.parse(raw)
  message = payload.is_a?(Hash) ? payload.dig("error", "message") : nil
  message.is_a?(String) && !message.empty? ? message : fallback
rescue JSON::ParserError
  fallback
end

def heartbeat(license_key, installation_id, api = API, app_id = APP_ID)
  nonce = SecureRandom.urlsafe_base64(24)
  fingerprint = Digest::SHA256.hexdigest("kernauth-device-v1:#{installation_id}")
  body = {
    protocol_version: 1, public_app_id: app_id, client_version: "1.0.0", license_key: license_key,
    fingerprint_version: 1, device_fingerprint: fingerprint, installation_id: installation_id, nonce: nonce
  }
  uri = URI("#{api}/v1/client/heartbeat")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == "https"
  http.open_timeout = 10
  http.read_timeout = 10
  response = http.post(uri.path, JSON.generate(body), "content-type" => "application/json")
  raise api_message(response.body, "heartbeat failed (#{response.code})") unless response.is_a?(Net::HTTPSuccess)
  payload = JSON.parse(response.body)
  raise "heartbeat failed" unless payload.is_a?(Hash) && payload["ok"] == true
end

def request(mode, license_key, installation_id, api = API, app_id = APP_ID, public_key = PUBLIC_KEY)
  nonce = SecureRandom.urlsafe_base64(24)
  fingerprint = Digest::SHA256.hexdigest("kernauth-device-v1:#{installation_id}")
  body = {
    protocol_version: 1, public_app_id: app_id, client_version: "1.0.0", license_key: license_key,
    fingerprint_version: 1, device_fingerprint: fingerprint, installation_id: installation_id, nonce: nonce
  }
  uri = URI("#{api}/v1/client/#{mode}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = uri.scheme == "https"
  http.open_timeout = 10
  http.read_timeout = 10
  response = http.post(uri.path, JSON.generate(body), "content-type" => "application/json")
  raise api_message(response.body, "#{mode} failed (#{response.code})") unless response.is_a?(Net::HTTPSuccess)

  grant = JSON.parse(response.body)
  raise "Invalid or expired signed entitlement" unless verify_grant(grant, nonce, app_id, public_key)

  grant["entitlement"]
end

def license_key
  env = ENV.fetch("KERN_LICENSE_KEY", "").strip
  return env unless env.empty?

  print "Enter license: " if $stdin.tty?
  $stdin.gets.to_s.strip
end

def installation_id
  env = ENV.fetch("KERN_INSTALLATION_ID", "").strip
  return env unless env.empty?
  hwid = machine_hwid.strip
  return hwid if hwid.match?(/\A[A-Za-z0-9_-]{8,64}\z/)
  raise "Could not read the HWID"
end

def machine_hwid
  case RUBY_PLATFORM
  when /mswin|mingw|windows/i
    `powershell.exe -NoProfile -Command "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"`
  when /darwin/
    output = `ioreg -rd1 -c IOPlatformExpertDevice`
    output[/\"IOPlatformUUID\" = \"([^\"]+)\"/, 1] || ""
  else
    File.read("/etc/machine-id")
  end
end

if __FILE__ == $PROGRAM_NAME
  app = KernAuth.new
  key = license_key
  hwid = installation_id
  raise app.message unless app.validate(key, hwid)

  ent = app.entitlement
  puts "Status: #{ent['status']}"
  puts "Features: #{ent['features']}"
  puts "License: #{ent['license_id']}"
  puts "Check expires: #{ent['expires_at']}"
  loop do
    sleep 60
    begin
      heartbeat(key, hwid, app.api, app.app_id)
    rescue StandardError => error
      puts error.message
      exit 1
    end
  end
end
