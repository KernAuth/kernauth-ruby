# frozen_string_literal: true

require "json"
require "time"
require_relative "kernauth"

fixture = JSON.parse(File.read("vectors.json"))
now = Time.iso8601("2026-01-01T00:01:00Z")
fixture["vectors"].each do |vector|
  ent = vector["fields"]
  grant = { "entitlement" => ent, "signature" => vector["signature"] }
  raise "#{vector["name"]} canonical" unless canonical(ent) == vector["canonical"]

  expiry = Time.iso8601(ent["expires_at"])
  ok = verify_grant(grant, ent["nonce"], ent["application_id"], ent["key_id"], vector["public_key"], now)
  bad_nonce = verify_grant(grant, "wrong", ent["application_id"], ent["key_id"], vector["public_key"], now)
  bad_app = verify_grant(grant, ent["nonce"], "pub_other_app", ent["key_id"], vector["public_key"], now)
  bad_key = verify_grant(grant, ent["nonce"], ent["application_id"], "wrong-key", vector["public_key"], now)
  bad_sig = verify_grant(grant.merge("signature" => "#{vector["signature"]}AA"), ent["nonce"], ent["application_id"], ent["key_id"], vector["public_key"], now)
  expired = verify_grant(grant, ent["nonce"], ent["application_id"], ent["key_id"], vector["public_key"], expiry)
  tampered = ent.merge("device_id" => "other")
  bad_device = verify_grant({ "entitlement" => tampered, "signature" => vector["signature"] }, ent["nonce"], ent["application_id"], ent["key_id"], vector["public_key"], now)
  revoked = ent.merge("status" => "revoked")
  bad_status = verify_grant({ "entitlement" => revoked, "signature" => vector["signature"] }, ent["nonce"], ent["application_id"], ent["key_id"], vector["public_key"], now)
  raise vector["name"] unless ok && !bad_nonce && !bad_app && !bad_key && !bad_sig && !expired && !bad_device && !bad_status
end
puts "Ruby vectors passed"
