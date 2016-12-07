# frozen_string_literal: true
module Msf::Module::Search
  #
  # This provides a standard set of search filters for every module.
  # The search terms are in the form of:
  #   {
  #     "text" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ],
  #     "cve" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ]
  #   }
  #
  # Returns true on no match, false on match
  #
  def search_filter(search_string)
    return false unless search_string

    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = search_string.split(/\"/).collect { |t| t.strip == t ? t : t.split(' ') }.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |t|
      f, v = t.split(":", 2)
      unless v
        v = f
        f = 'text'
      end
      next if v.empty?
      f.downcase!
      v.downcase!
      res[f] ||= [ [], [] ]
      if v[0, 1] == "-"
        next if v.length == 1
        res[f][1] << v[1, v.length - 1]
      else
        res[f][0] << v
      end
    end

    k = res

    refs = references.map { |x| [x.ctx_id, x.ctx_val].join("-") }
    is_server    = (respond_to?(:stance) && (stance == "aggressive"))
    is_client    = (respond_to?(:stance) && (stance == "passive"))

    [0, 1].each do |mode|
      match = false
      k.keys.each do |t|
        next if k[t][mode].empty?

        k[t][mode].each do |w|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == 0

          # Convert into a case-insensitive regex
          r = Regexp.new(Regexp.escape(w), true)

          case t
          when 'text'
            terms = [name, fullname, description] + refs + author.map(&:to_s)
            terms += targets.map(&:name) if respond_to?(:targets) && targets
            match = [t, w] if terms.any? { |x| x =~ r }
          when 'name'
            match = [t, w] if name =~ r
          when 'path'
            match = [t, w] if fullname =~ r
          when 'author'
            match = [t, w] if author.map(&:to_s).any? { |a| a =~ r }
          when 'os', 'platform'
            match = [t, w] if platform_to_s =~ r || arch_to_s =~ r
            if !match && respond_to?(:targets) && targets
              match = [t, w] if targets.map(&:name).any? { |t| t =~ r }
            end
          when 'port'
            match = [t, w] if datastore['RPORT'].to_s =~ r
          when 'type'
            match = [t, w] if Msf::MODULE_TYPES.any? { |modt| (w == modt) && (type == modt) }
          when 'app'
            match = [t, w] if (w == "server") && is_server
            match = [t, w] if (w == "client") && is_client
          when 'cve'
            match = [t, w] if refs.any? { |ref| ref =~ /^cve\-/i && ref =~ r }
          when 'bid'
            match = [t, w] if refs.any? { |ref| ref =~ /^bid\-/i && ref =~ r }
          when 'edb'
            match = [t, w] if refs.any? { |ref| ref =~ /^edb\-/i && ref =~ r }
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        return true if (mode == 0) && !match
      end
      # Filter this module if we matched an exclusion keyword (-value)
      return true if (mode == 1) && match
    end

    false
  end
end
