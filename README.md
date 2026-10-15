# KernAuth Ruby example

Paste the public app ID, key ID, and public key from Developers into `kernauth.rb`. Ruby 3.1 or newer with OpenSSL.

## Instance

```ruby
app = KernAuth.new(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__KEY_ID__",
  "__PUBLIC_KEY__",
)
```

## Validate

```ruby
raise app.message unless app.validate(license, installation)
puts "Status: #{app.entitlement['status']}"
puts "Features: #{app.entitlement['features']}"
puts "License: #{app.entitlement['license_id']}"
puts "Check expires: #{app.entitlement['expires_at']}"
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
ruby test_kernauth.rb
ruby kernauth.rb
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
