# frozen_string_literal: true

require "yaml"

module Holons
  # Parsed identity from a HOLON.md file.
  HolonIdentity = Struct.new(
    :uuid, :given_name, :family_name, :motto, :composer,
    :clade, :status, :born, :lang,
    keyword_init: true
  )

  module Identity
    # Parse a HOLON.md file.
    def self.parse_holon(path)
      text = File.read(path)
      raise "#{path}: missing YAML frontmatter" unless text.start_with?("---")

      end_idx = text.index("---", 3)
      raise "#{path}: unterminated frontmatter" unless end_idx

      frontmatter = text[3...end_idx].strip
      data = YAML.safe_load(frontmatter) || {}

      HolonIdentity.new(
        uuid: data["uuid"].to_s,
        given_name: data["given_name"].to_s,
        family_name: data["family_name"].to_s,
        motto: data["motto"].to_s,
        composer: data["composer"].to_s,
        clade: data["clade"].to_s,
        status: data["status"].to_s,
        born: data["born"].to_s,
        lang: data["lang"].to_s
      )
    end
  end
end
