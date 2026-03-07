# frozen_string_literal: true

require "yaml"

module Holons
  # Parsed identity from a holon.yaml file.
  HolonIdentity = Struct.new(
    :uuid, :given_name, :family_name, :motto, :composer,
    :clade, :status, :born, :lang,
    keyword_init: true
  )

  module Identity
    # Parse a holon.yaml file.
    def self.parse_holon(path)
      text = File.read(path)
      data = YAML.safe_load(text) || {}
      raise "#{path}: holon.yaml must be a YAML mapping" unless data.is_a?(Hash)

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
