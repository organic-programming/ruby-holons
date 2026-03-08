# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require_relative "../lib/holons"

class DescribeTest < Minitest::Test
  def test_build_response_from_echo_proto
    response = Holons::Describe.build_response(
      proto_dir: File.join(echo_holon_dir, "protos"),
      holon_yaml_path: File.join(echo_holon_dir, "holon.yaml")
    )

    assert_equal "echo-server", response.slug
    assert_equal "Reply precisely.", response.motto
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

  def test_provider_describe_returns_response
    provider = Holons::Describe.service(
      proto_dir: File.join(echo_holon_dir, "protos"),
      holon_yaml_path: File.join(echo_holon_dir, "holon.yaml")
    )

    response = provider.describe(Holons::Describe::DescribeRequest.new)
    assert_equal "echo-server", response.slug
    assert_equal ["echo.v1.Echo"], response.services.map(&:name)
  end

  def test_build_response_without_proto_files
    Dir.mktmpdir("ruby-holons-describe-") do |dir|
      holon_yaml = File.join(dir, "holon.yaml")
      File.write(holon_yaml, <<~YAML)
        given_name: Empty
        family_name: Holon
        motto: Still available.
      YAML

      response = Holons::Describe.build_response(
        proto_dir: File.join(dir, "protos"),
        holon_yaml_path: holon_yaml
      )

      assert_equal "empty-holon", response.slug
      assert_equal "Still available.", response.motto
      assert_empty response.services
    end
  end

  private

  def echo_holon_dir
    File.expand_path("../../go-holons/pkg/describe/testdata/echoholon", __dir__)
  end
end
