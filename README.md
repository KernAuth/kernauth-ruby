# KernAuth Ruby example

Paste the public app ID from Developers into `main.rb`. Ruby 3.1 or newer.

## Start

```ruby
app = KernAuth.new("https://api.kernauth.com", "__PUBLIC_APP_ID__")
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
ruby test_kernauth.rb
ruby main.rb
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
