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
    def self.parse(path)
      case File.basename(path.to_s)
      when "holon.proto"
        parse_proto_manifest(path)
      else
        parse_holon(path)
      end
    end

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

    def self.parse_proto_manifest(path)
      text = File.read(path)
      manifest_block = extract_braced_block(text, "option (holons.v1.manifest)")
      identity_block = extract_named_block(manifest_block, "identity")

      HolonIdentity.new(
        uuid: extract_string(identity_block, "uuid"),
        given_name: extract_string(identity_block, "given_name"),
        family_name: extract_string(identity_block, "family_name"),
        motto: extract_string(identity_block, "motto"),
        composer: extract_string(identity_block, "composer"),
        clade: "",
        status: extract_string(identity_block, "status"),
        born: extract_string(identity_block, "born"),
        lang: extract_string(manifest_block, "lang")
      )
    end

    def self.extract_named_block(text, field_name)
      match = text.match(/^\s*#{Regexp.escape(field_name)}\s*:\s*\{/m)
      return "" if match.nil?

      extract_braced_block(text, "{", match.begin(0) + match[0].index("{"))
    end

    def self.extract_string(text, field_name)
      match = text.match(/^\s*#{Regexp.escape(field_name)}\s*:\s*"([^"]*)"/m)
      return "" if match.nil?

      match[1].to_s
    end

    def self.extract_braced_block(text, needle, offset = nil)
      start = offset || text.index(needle)
      raise "#{needle} not found" if start.nil?

      brace_start = offset || text.index("{", start)
      raise "opening brace not found after #{needle}" if brace_start.nil?

      depth = 0
      in_string = false
      escaped = false

      text.each_char.with_index do |char, index|
        next if index < brace_start

        if in_string
          if escaped
            escaped = false
          elsif char == "\\"
            escaped = true
          elsif char == "\""
            in_string = false
          end
          next
        end

        case char
        when "\""
          in_string = true
        when "{"
          depth += 1
        when "}"
          depth -= 1
          return text[(brace_start + 1)...index] if depth.zero?
        end
      end

      raise "unterminated brace block for #{needle}"
    end
  end
end
