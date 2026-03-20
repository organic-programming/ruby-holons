# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require_relative "../lib/holons"

class DescribeTest < Minitest::Test
  def test_build_response_from_echo_proto
    with_echo_holon do |root|
      response = Holons::Describe.build_response(
        proto_dir: File.join(root, "protos")
      )
      identity = response.manifest.identity

      assert_equal "Echo", identity.given_name
      assert_equal "Server", identity.family_name
      assert_equal "Reply precisely.", identity.motto
      assert_equal 1, response.services.length

      service = response.services.first
      assert_equal "echo.v1.Echo", service.name
      assert_equal "Echo echoes request payloads for documentation tests.", service.description
      assert_equal 1, service.methods.length

      method = service.methods.first
      assert_equal "Ping", method.name
      assert_equal "Ping echoes the inbound message.", method.description
      assert_equal "echo.v1.PingRequest", method.input_type
      assert_equal "echo.v1.PingResponse", method.output_type
      assert_equal '{"message":"hello","sdk":"go-holons"}', method.example_input

      field = method.input_fields.find { |entry| entry.name == "message" }
      refute_nil field
      assert_equal "string", field.type
      assert_equal 1, field.number
      assert_equal "Message to echo back.", field.description
      assert_equal Holons::Describe::FieldLabel::REQUIRED, field.label
      assert field.required
      assert_equal '"hello"', field.example
    end
  end

  def test_provider_describe_returns_response
    with_echo_holon do |root|
      provider = Holons::Describe.service(
        proto_dir: File.join(root, "protos")
      )

      response = provider.describe(Holons::Describe::DescribeRequest.new)
      assert_equal "Echo", response.manifest.identity.given_name
      assert_equal ["echo.v1.Echo"], response.services.map(&:name)
    end
  end

  def test_build_response_without_proto_files
    Dir.mktmpdir("ruby-holons-describe-") do |dir|
      File.write(File.join(dir, "holon.proto"), <<~PROTO)
        syntax = "proto3";

        package holons.test.v1;

        option (holons.v1.manifest) = {
          identity: {
            uuid: "empty-holon-0000"
            given_name: "Empty"
            family_name: "Holon"
            motto: "Still available."
            composer: "describe-test"
            status: "draft"
            born: "2026-03-17"
          }
          lang: "ruby"
        };
      PROTO

      response = Holons::Describe.build_response(
        proto_dir: File.join(dir, "protos")
      )
      identity = response.manifest.identity

      assert_equal "Empty", identity.given_name
      assert_equal "Holon", identity.family_name
      assert_equal "Still available.", identity.motto
      assert_empty response.services
    end
  end

  def test_build_response_from_proto_manifest
    Dir.mktmpdir("ruby-holons-describe-proto-") do |dir|
      manifest_dir = File.join(dir, "api", "v1")
      FileUtils.mkdir_p(manifest_dir)
      manifest_path = File.join(manifest_dir, "holon.proto")
      File.write(manifest_path, <<~PROTO)
        syntax = "proto3";

        package echo.v1;

        import "holons/v1/manifest.proto";
        import "echo/v1/echo.proto";

        option (holons.v1.manifest) = {
          identity: {
            schema: "holon/v1"
            uuid: "echo-proto"
            given_name: "Echo"
            family_name: "Server"
            motto: "Reply precisely."
            composer: "describe-test"
            status: "draft"
            born: "2026-03-16"
          }
          description: "Proto manifest fixture."
          lang: "ruby"
          kind: "native"
          build: {
            runner: "ruby"
            main: "./cmd/main.rb"
          }
          artifacts: {
            binary: "echo-server"
          }
        };
      PROTO

      response = Holons::Describe.build_response(
        proto_dir: File.join(echo_holon_dir, "protos"),
        manifest_path: manifest_path
      )

      assert_equal "Echo", response.manifest.identity.given_name
      assert_equal "Reply precisely.", response.manifest.identity.motto
      assert_equal ["echo.v1.Echo"], response.services.map(&:name)
    end
  end

  private

  def echo_holon_dir
    File.expand_path("../../go-holons/pkg/describe/testdata/echoholon", __dir__)
  end

  def with_echo_holon
    Dir.mktmpdir("ruby-holons-describe-echo-") do |dir|
      FileUtils.cp_r(File.join(echo_holon_dir, "protos"), File.join(dir, "protos"))
      File.write(File.join(dir, "holon.proto"), <<~PROTO)
        syntax = "proto3";

        package holons.test.v1;

        option (holons.v1.manifest) = {
          identity: {
            uuid: "echo-server-0000"
            given_name: "Echo"
            family_name: "Server"
            motto: "Reply precisely."
            composer: "describe-test"
            status: "draft"
            born: "2026-03-17"
          }
          lang: "ruby"
        };
      PROTO
      yield dir
    end
  end
end
