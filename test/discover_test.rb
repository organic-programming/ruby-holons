# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"
require_relative "../lib/holons"

class DiscoverTest < Minitest::Test
  def test_discover_recurses_skips_and_dedups
    Dir.mktmpdir("holons-ruby-discover-") do |root|
      write_holon(root, "holons/alpha", uuid: "uuid-alpha", given_name: "Alpha", family_name: "Go", binary: "alpha-go")
      write_holon(root, "nested/beta", uuid: "uuid-beta", given_name: "Beta", family_name: "Rust", binary: "beta-rust")
      write_holon(root, "nested/dup/alpha", uuid: "uuid-alpha", given_name: "Alpha", family_name: "Go", binary: "alpha-go")

      %w[.git/hidden .op/hidden node_modules/hidden vendor/hidden build/hidden .cache/hidden].each do |skipped|
        write_holon(root, skipped, uuid: "ignored-#{File.basename(skipped)}", given_name: "Ignored", family_name: "Holon", binary: "ignored-holon")
      end

      entries = Holons.discover(root)
      assert_equal 2, entries.length

      alpha = entries.find { |entry| entry.uuid == "uuid-alpha" }
      assert_equal "alpha-go", alpha.slug
      assert_equal "holons/alpha", alpha.relative_path
      assert_equal "go-module", alpha.manifest.build.runner

      beta = entries.find { |entry| entry.uuid == "uuid-beta" }
      assert_equal "nested/beta", beta.relative_path
    end
  end

  def test_discover_local_and_find_helpers
    Dir.mktmpdir("holons-ruby-find-") do |root|
      write_holon(
        root,
        "rob-go",
        uuid: "c7f3a1b2-1111-1111-1111-111111111111",
        given_name: "Rob",
        family_name: "Go",
        binary: "rob-go"
      )

      original_dir = Dir.pwd
      original_oppath = ENV["OPPATH"]
      original_opbin = ENV["OPBIN"]
      begin
        Dir.chdir(root)
        ENV["OPPATH"] = File.join(root, "runtime")
        ENV["OPBIN"] = File.join(root, "runtime", "bin")

        local = Holons.discover_local
        assert_equal 1, local.length
        assert_equal "rob-go", local.first.slug

        by_slug = Holons.find_by_slug("rob-go")
        refute_nil by_slug
        assert_equal "c7f3a1b2-1111-1111-1111-111111111111", by_slug.uuid

        by_uuid = Holons.find_by_uuid("c7f3a1b2")
        refute_nil by_uuid
        assert_equal "rob-go", by_uuid.slug

        assert_nil Holons.find_by_slug("missing")
      ensure
        Dir.chdir(original_dir)
        ENV["OPPATH"] = original_oppath
        ENV["OPBIN"] = original_opbin
      end
    end
  end

  private

  def write_holon(root, relative_dir, uuid:, given_name:, family_name:, binary:)
    dir = File.join(root, relative_dir)
    FileUtils.mkdir_p(dir)
    File.write(File.join(dir, "holon.yaml"), <<~YAML)
      schema: holon/v0
      uuid: "#{uuid}"
      given_name: "#{given_name}"
      family_name: "#{family_name}"
      motto: "Test"
      composer: "test"
      clade: deterministic/pure
      status: draft
      born: "2026-03-07"
      generated_by: test
      kind: native
      build:
        runner: go-module
      artifacts:
        binary: #{binary}
    YAML
  end
end
