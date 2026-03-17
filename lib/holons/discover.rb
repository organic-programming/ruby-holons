# frozen_string_literal: true

require "pathname"
require "yaml"

module Holons
  HolonBuild = Struct.new(:runner, :main, keyword_init: true)
  HolonArtifacts = Struct.new(:binary, :primary, keyword_init: true)
  HolonManifest = Struct.new(:kind, :build, :artifacts, keyword_init: true)
  HolonEntry = Struct.new(
    :slug, :uuid, :dir, :relative_path, :origin, :identity, :manifest,
    keyword_init: true
  )

  class << self
    def discover(root)
      discover_in_root(root, "local")
    end

    def discover_local
      discover(Dir.pwd)
    end

    def discover_all
      entries = []
      seen = {}

      [[Dir.pwd, "local"], [opbin, "$OPBIN"], [cache_dir, "cache"]].each do |root, origin|
        discover_in_root(root, origin).each do |entry|
          key = entry.uuid.to_s.strip
          key = entry.dir if key.empty?
          next if seen[key]

          seen[key] = true
          entries << entry
        end
      end

      entries
    end

    def find_by_slug(slug)
      needle = slug.to_s.strip
      return nil if needle.empty?

      match = nil
      discover_all.each do |entry|
        next unless entry.slug == needle

        if !match.nil? && match.uuid != entry.uuid
          raise "ambiguous holon \"#{needle}\""
        end

        match = entry
      end
      match
    end

    def discover_by_slug(slug)
      find_by_slug(slug)
    end

    def find_by_uuid(prefix)
      needle = prefix.to_s.strip
      return nil if needle.empty?

      match = nil
      discover_all.each do |entry|
        next unless entry.uuid.start_with?(needle)

        if !match.nil? && match.uuid != entry.uuid
          raise "ambiguous UUID prefix \"#{needle}\""
        end

        match = entry
      end
      match
    end

    private

    def discover_in_root(root, origin)
      resolved_root = File.expand_path(root.to_s.strip.empty? ? Dir.pwd : root.to_s)
      return [] unless File.directory?(resolved_root)

      entries_by_key = {}
      ordered_keys = []
      scan_dir(resolved_root, resolved_root, origin, entries_by_key, ordered_keys)

      ordered_keys
        .filter { |key| entries_by_key.key?(key) }
        .map { |key| entries_by_key[key] }
        .sort_by { |entry| [entry.relative_path, entry.uuid] }
    end

    def scan_dir(root, dir, origin, entries_by_key, ordered_keys)
      Dir.each_child(dir) do |name|
        child = File.join(dir, name)
        if File.directory?(child)
          next if should_skip_dir?(root, child, name)

          scan_dir(root, child, origin, entries_by_key, ordered_keys)
          next
        end
        next unless manifest_file?(root, child, name)

        begin
          identity = Identity.parse(child)
          manifest = parse_manifest(child)
        rescue StandardError
          next
        end

        holon_dir = manifest_root(child)
        entry = HolonEntry.new(
          slug: slug_for(identity),
          uuid: identity.uuid.to_s,
          dir: holon_dir,
          relative_path: relative_path(root, holon_dir),
          origin: origin,
          identity: identity,
          manifest: manifest
        )

        key = entry.uuid.to_s.strip
        key = entry.dir if key.empty?
        if entries_by_key.key?(key)
          existing = entries_by_key[key]
          entries_by_key[key] = entry if path_depth(entry.relative_path) < path_depth(existing.relative_path)
          next
        end

        entries_by_key[key] = entry
        ordered_keys << key
      end
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end

    def parse_manifest(path)
      return parse_proto_manifest(path) if File.basename(path) == "holon.proto"

      data = YAML.safe_load(File.read(path)) || {}
      raise "#{path}: holon.yaml must be a YAML mapping" unless data.is_a?(Hash)

      build = data["build"].is_a?(Hash) ? data["build"] : {}
      artifacts = data["artifacts"].is_a?(Hash) ? data["artifacts"] : {}
      HolonManifest.new(
        kind: data["kind"].to_s,
        build: HolonBuild.new(
          runner: build["runner"].to_s,
          main: build["main"].to_s
        ),
        artifacts: HolonArtifacts.new(
          binary: artifacts["binary"].to_s,
          primary: artifacts["primary"].to_s
        )
      )
    end

    def parse_proto_manifest(path)
      text = File.read(path)
      manifest_block = Identity.extract_braced_block(text, "option (holons.v1.manifest)")
      build_block = Identity.extract_named_block(manifest_block, "build")
      artifacts_block = Identity.extract_named_block(manifest_block, "artifacts")

      HolonManifest.new(
        kind: Identity.extract_string(manifest_block, "kind"),
        build: HolonBuild.new(
          runner: Identity.extract_string(build_block, "runner"),
          main: Identity.extract_string(build_block, "main")
        ),
        artifacts: HolonArtifacts.new(
          binary: Identity.extract_string(artifacts_block, "binary"),
          primary: Identity.extract_string(artifacts_block, "primary")
        )
      )
    end

    def slug_for(identity)
      given = identity.given_name.to_s.strip
      family = identity.family_name.to_s.strip.sub(/\?\z/, "")
      return "" if given.empty? && family.empty?

      "#{given}-#{family}".strip.downcase.tr(" ", "-").gsub(/\A-+|-+\z/, "")
    end

    def should_skip_dir?(root, dir, name)
      return false if File.expand_path(dir) == File.expand_path(root)

      %w[.git .op node_modules vendor build].include?(name) || name.start_with?(".")
    end

    def manifest_file?(root, path, name)
      return false unless File.file?(path)
      return true if name == "holon.yaml"
      return false unless name == "holon.proto"

      relative = relative_path(root, path)
      relative == "api/v1/holon.proto" || relative.end_with?("/api/v1/holon.proto")
    end

    def manifest_root(path)
      return File.expand_path(File.dirname(path)) unless File.basename(path) == "holon.proto"

      File.expand_path(File.join(File.dirname(path), "..", ".."))
    end

    def relative_path(root, dir)
      rel = Pathname.new(dir).relative_path_from(Pathname.new(root)).to_s
      rel.empty? ? "." : rel.tr(File::SEPARATOR, "/")
    rescue ArgumentError
      dir.tr(File::SEPARATOR, "/")
    end

    def path_depth(relative_path)
      trimmed = relative_path.to_s.strip.gsub(%r{\A/+|/+\z}, "")
      return 0 if trimmed.empty? || trimmed == "."

      trimmed.split("/").length
    end

    def op_path
      configured = ENV.fetch("OPPATH", "").strip
      return File.expand_path(configured) unless configured.empty?

      File.expand_path("~/.op")
    end

    def opbin
      configured = ENV.fetch("OPBIN", "").strip
      return File.expand_path(configured) unless configured.empty?

      File.join(op_path, "bin")
    end

    def cache_dir
      File.join(op_path, "cache")
    end
  end
end
