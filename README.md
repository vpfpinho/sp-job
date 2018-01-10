# Sp::Job

# Execute the job

The job is executed method perform of the job class. If the tube is called 'park-fun' 

```ruby
  class ParkFun

  def self.perform (job)

  end

```

## Return the job result

use send_response(result: object)

## Report a non-fatal error

return report_error(message: 'i18n_message_key", args)

## Report a fatal error

Use raise_error(message:  'i18n_message_key", args)

# Database access 

Use the `db` object. 

## db.exec

The first argument is the query string followed by a variable number of arguments that are bound to the query.

```ruby
   db.exec('SELECT fun FROM public.park where id=$1', id_value)
```

Returns an xxx

## db.query

# Redis

Use the redis accessor to obtain a Redis object already connected 

# Sending mails

Call send_mail

# Job configuration

Use config

# Logging 

Use logger

