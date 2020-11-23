
class Hash
    # new method to remove the dependency of HashWithIndifferentAccess
    def symbolize_names
      return JSON.parse(self.to_json, symbolize_names: true) rescue self
    end
end
