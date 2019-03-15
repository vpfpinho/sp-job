module RFC822
  module Patterns
    ATOM     = "[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\u00ff]+"
    QTEXT    = "[^\\x0d\\x22\\x5c\\u0080-\\u00ff]"
    QPAIR    = "\\x5c[\\x00-\\x7f]"
    QSTRING  = "\\x22(?:#{QTEXT}|#{QPAIR})*\\x22"
    WORD     = "(?:#{ATOM}|#{QSTRING})"
    LOCAL_PT = "#{WORD}(?:\\x2e#{WORD})*"
    ADDRESS  = "#{LOCAL_PT}\\x40(?:#{URI::REGEXP::PATTERN::HOSTNAME})?#{ATOM}"
  end

  EMAIL = /\A#{Patterns::ADDRESS}\z/
end