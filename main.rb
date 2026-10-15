require_relative "kernauth"

def license_key
  from_env = ENV["KERN_LICENSE_KEY"].to_s.strip
  return from_env unless from_env.empty?
  print "Enter license: " if $stdin.tty?
  $stdin.gets.to_s.strip
end

app = KernAuth.new("https://api.kernauth.com", "__PUBLIC_APP_ID__")
unless app.check(license_key)
  puts app.message
  exit 1
end
puts "Status: active"
puts app.expires_at ? "Expires: #{app.expires_at}" : "Expires: Lifetime"
