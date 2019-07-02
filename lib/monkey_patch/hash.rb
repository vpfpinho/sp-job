# Monkey patch for configuration deep merge
class ::Hash

  def config_merge (second)

    second.each do |skey, sval|
      if self.has_key?(skey+'!')
        self[skey] = self[skey+'!']
        self.delete(skey+'!')
        next
      elsif skey[-1] == '!'
        tkey = skey[0..-2]
        if self.has_key?(tkey)
          if Array === self[tkey] && Array === sval
            self[tkey] = self[tkey] | sval
          elsif Hash === self[tkey] && Hash === sval
            self[tkey].config_merge(sval)
          else
            raise "Error can't merge #{skey} with different types"
          end
        end
      end

      if ! self.has_key?(skey)
        self[skey] = sval
      else
        if Array === self[skey] && Array === sval
          self[skey] = self[skey] | sval
        elsif Hash === self[skey] && Hash === sval
          self[skey].config_merge(sval)
        end
      end
    end
  end

  def clean_keys!
    tmp = Hash.new

    self.each do |key, val|
      if Hash === val
        val.clean_keys!
      end

      if key[-1] == '!'
        tmp[key[0..-2]] = val
        self.delete(key)
      end
    end

    self.merge! tmp
  end

end # Hash monkey patch