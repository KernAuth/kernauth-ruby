require_relative "kernauth"

body = check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP")
raise "body" unless body == {
  "protocol_version" => 1,
  "public_app_id" => "pub_harbor_desktop",
  "client_version" => "1.0.0",
  "license_key" => "KERN-ABCD-EFGH-IJKL-MNOP",
}
raise "message" unless api_message({ "error" => { "message" => "Update required" } }, "no") == "Update required"
raise "fallback" unless api_message({}, "no") == "no"
puts "Ruby check passed"
