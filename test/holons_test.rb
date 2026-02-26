# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"
require "securerandom"
require "tempfile"
require "tmpdir"
require "timeout"
require_relative "../lib/holons"

class HolonsTest < Minitest::Test
  def test_scheme
    assert_equal "tcp", Holons::Transport.scheme("tcp://:9090")
    assert_equal "unix", Holons::Transport.scheme("unix:///tmp/x.sock")
    assert_equal "stdio", Holons::Transport.scheme("stdio://")
    assert_equal "mem", Holons::Transport.scheme("mem://")
    assert_equal "ws", Holons::Transport.scheme("ws://127.0.0.1:8080/grpc")
    assert_equal "wss", Holons::Transport.scheme("wss://example.com:443/grpc")
  end

  def test_default_uri
    assert_equal "tcp://:9090", Holons::Transport::DEFAULT_URI
  end

  def test_tcp_listen
    listener = nil
    begin
      listener = Holons::Transport.listen("tcp://127.0.0.1:0")
      assert_instance_of Holons::Transport::Listener::Tcp, listener
      assert listener.socket.local_address.ip_port > 0
    rescue Errno::EPERM => e
      skip_bind_denied(e)
    ensure
      listener&.socket&.close unless listener.nil? || listener.socket.closed?
    end
  end

  def test_parse_uri_wss_defaults
    parsed = Holons::Transport.parse_uri("wss://example.com:8443")
    assert_equal "wss", parsed.scheme
    assert_equal "example.com", parsed.host
    assert_equal 8443, parsed.port
    assert_equal "/grpc", parsed.path
    assert parsed.secure
  end

  def test_stdio_and_mem_variants
    stdio = Holons::Transport.listen("stdio://")
    mem = Holons::Transport.listen("mem://")

    assert_instance_of Holons::Transport::Listener::Stdio, stdio
    assert_instance_of Holons::Transport::Listener::Mem, mem
    assert_equal "stdio://", stdio.address
    assert_equal "mem://", mem.address
  end

  def test_runtime_tcp_roundtrip
    listener = nil
    accepted = nil
    client = nil
    accept_thread = nil
    begin
      listener = Holons::Transport.listen("tcp://127.0.0.1:0")
      tcp = listener

      accept_thread = Thread.new do
        accepted = Holons::Transport.accept(tcp)
      end

      client = TCPSocket.new("127.0.0.1", tcp.socket.local_address.ip_port)
      accept_thread.join

      client.write("ping")
      payload = Holons::Transport.conn_read(accepted, 4)
      assert_equal "ping", payload
    rescue Errno::EPERM => e
      skip_bind_denied(e)
    ensure
      Holons::Transport.close_connection(accepted) unless accepted.nil?
      client.close unless client.nil? || client.closed?
      listener&.socket&.close unless listener.nil? || listener.socket.closed?
      accept_thread&.kill if accept_thread&.alive?
    end
  end

  def test_runtime_stdio_single_accept
    stdio = Holons::Transport.listen("stdio://")
    conn = Holons::Transport.accept(stdio)
    assert_equal "stdio", conn.scheme
    Holons::Transport.close_connection(conn)
    assert_raises(RuntimeError) { Holons::Transport.accept(stdio) }
  end

  def test_runtime_mem_roundtrip
    mem = Holons::Transport.listen("mem://ruby-test")
    client = Holons::Transport.mem_dial(mem)
    server = Holons::Transport.accept(mem)

    Holons::Transport.conn_write(client, "mem")
    payload = Holons::Transport.conn_read(server, 3)
    assert_equal "mem", payload

    Holons::Transport.close_connection(server)
    Holons::Transport.close_connection(client)
  end

  def test_ws_runtime_unsupported
    ws = Holons::Transport.listen("ws://127.0.0.1:8080/grpc")
    assert_raises(RuntimeError) { Holons::Transport.accept(ws) }
  end

  def test_ws_variant
    ws = Holons::Transport.listen("ws://127.0.0.1:8080/holon")
    assert_instance_of Holons::Transport::Listener::WS, ws
    assert_equal "127.0.0.1", ws.host
    assert_equal 8080, ws.port
    assert_equal "/holon", ws.path
    refute ws.secure
  end

  def test_unsupported_uri
    assert_raises(ArgumentError) { Holons::Transport.listen("ftp://host") }
  end

  def test_parse_flags_listen
    assert_equal "tcp://:8080",
      Holons::Serve.parse_flags(["--listen", "tcp://:8080"])
  end

  def test_parse_flags_port
    assert_equal "tcp://:3000",
      Holons::Serve.parse_flags(["--port", "3000"])
  end

  def test_parse_flags_default
    assert_equal Holons::Transport::DEFAULT_URI,
      Holons::Serve.parse_flags([])
  end

  def test_parse_holon
    tmp = Tempfile.new(["holon", ".md"])
    tmp.write("---\nuuid: \"abc-123\"\ngiven_name: \"test\"\n" \
              "family_name: \"Test\"\nlang: \"ruby\"\n---\n# test\n")
    tmp.flush

    id = Holons::Identity.parse_holon(tmp.path)
    assert_equal "abc-123", id.uuid
    assert_equal "test", id.given_name
    assert_equal "ruby", id.lang

    tmp.close!
  end

  def test_parse_missing_frontmatter
    tmp = Tempfile.new(["nofm", ".md"])
    tmp.write("# No frontmatter\n")
    tmp.flush
    assert_raises(RuntimeError) { Holons::Identity.parse_holon(tmp.path) }
    tmp.close!
  end

  private

  def skip_bind_denied(error)
    skip "local socket bind is denied in this environment: #{error.message}"
  end
end

class CertificationArtifactsTest < Minitest::Test
  def test_cert_json_declares_echo_executables_and_level1_dial
    cert = JSON.parse(File.read(File.join(sdk_dir, "cert.json")))

    assert_equal "./bin/echo-server", cert.dig("executables", "echo_server")
    assert_equal "./bin/echo-client", cert.dig("executables", "echo_client")
    assert_equal "./bin/holon-rpc-server", cert.dig("executables", "holon_rpc_server")

    expected_capabilities = {
      "grpc_dial_tcp" => true,
      "grpc_dial_stdio" => true,
      "grpc_dial_unix" => true,
      "grpc_dial_ws" => true,
      "holon_rpc_server" => true
    }
    actual_capabilities = expected_capabilities.keys.each_with_object({}) do |capability, result|
      result[capability] = cert.dig("capabilities", capability)
    end

    assert_equal expected_capabilities, actual_capabilities
  end

  def test_echo_scripts_exist_and_are_executable
    echo_client = File.join(sdk_dir, "bin", "echo-client")
    echo_server = File.join(sdk_dir, "bin", "echo-server")
    holon_rpc_server = File.join(sdk_dir, "bin", "holon-rpc-server")

    assert File.file?(echo_client), "missing #{echo_client}"
    assert File.file?(echo_server), "missing #{echo_server}"
    assert File.file?(holon_rpc_server), "missing #{holon_rpc_server}"
    assert File.executable?(echo_client), "echo-client is not executable"
    assert File.executable?(echo_server), "echo-server is not executable"
    assert File.executable?(holon_rpc_server), "holon-rpc-server is not executable"
  end

  def test_echo_client_script_passes_expected_arguments_to_go
    script = File.join(sdk_dir, "bin", "echo-client")
    args = capture_forwarded_args(script, "--message", "ruby-cert", "stdio://")

    assert_equal "run", args[0]
    assert args.any? { |arg| arg.include?("kotlin-holons/cmd/echo-client-go/main.go") },
      "unexpected helper path arguments: #{args.inspect}"
    assert_flag_value(args, "--sdk", "ruby-holons")
    assert_flag_value(args, "--server-sdk", "go-holons")
    assert_flag_value(args, "--message", "ruby-cert")
    assert_equal "stdio://", args[-1]
  end

  def test_echo_server_script_passes_expected_arguments_to_go
    script = File.join(sdk_dir, "bin", "echo-server")
    args = capture_forwarded_args(script, "--listen", "stdio://")

    assert_equal "run", args[0]
    assert args.any? { |arg| arg.include?("ruby-holons/cmd/echo-server-go/main.go") },
      "unexpected helper path arguments: #{args.inspect}"
    assert_flag_value(args, "--sdk", "ruby-holons")
    assert_flag_value(args, "--listen", "stdio://")
  end

  def test_echo_server_script_forwards_sleep_ms
    script = File.join(sdk_dir, "bin", "echo-server")
    args = capture_forwarded_args(script, "--sleep-ms", "250", "--listen", "stdio://")

    assert_equal "run", args[0]
    assert_flag_value(args, "--sleep-ms", "250")
    assert_flag_value(args, "--listen", "stdio://")
  end

  def test_holon_rpc_server_script_passes_expected_arguments_to_go
    script = File.join(sdk_dir, "bin", "holon-rpc-server")
    args = capture_forwarded_args(script, "ws://127.0.0.1:0/rpc")

    assert_equal "run", args[0]
    assert args.any? { |arg| arg.include?("kotlin-holons/cmd/holon-rpc-server-go/main.go") },
      "unexpected helper path arguments: #{args.inspect}"
    assert_flag_value(args, "--sdk", "ruby-holons")
    assert_equal "ws://127.0.0.1:0/rpc", args[-1]
  end

  def test_holon_rpc_server_script_accepts_uri_before_flags
    script = File.join(sdk_dir, "bin", "holon-rpc-server")
    args = capture_forwarded_args(script, "ws://127.0.0.1:0/rpc", "--once")

    assert_equal "run", args[0]
    assert_flag_value(args, "--sdk", "ruby-holons")
    assert_includes args, "--once"
    assert_equal "ws://127.0.0.1:0/rpc", args[-1]
  end

  def test_echo_client_can_dial_go_ws_server
    with_go_echo_server("ws://127.0.0.1:0/grpc") do |uri|
      stdout, stderr, status = Open3.capture3(
        { "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests") },
        File.join(sdk_dir, "bin", "echo-client"),
        "--message",
        "ws-cert",
        uri,
        chdir: sdk_dir
      )

      assert status.success?, "ws dial failed with stderr: #{stderr}"

      result = JSON.parse(stdout)
      assert_equal "pass", result["status"]
      assert_equal "go-holons", result["response_sdk"]
    end
  end

  def test_echo_server_timeout_propagates_deadline_and_stays_healthy
    with_ruby_echo_server("--sleep-ms", "5000", "--listen", "tcp://127.0.0.1:0") do |uri|
      _timeout_out, timeout_err, timeout_status = run_go_echo_client(
        "--server-sdk",
        "ruby-holons",
        "--timeout-ms",
        "2000",
        "--message",
        "cert-l5-timeout",
        uri
      )
      refute timeout_status.success?, "expected timeout probe to fail"
      assert_match(/DeadlineExceeded|deadline exceeded/, timeout_err)

      follow_out, follow_err, follow_status = run_go_echo_client(
        "--server-sdk",
        "ruby-holons",
        "--timeout-ms",
        "8000",
        "--message",
        "cert-l5-timeout-followup",
        uri
      )
      assert follow_status.success?, "follow-up probe failed with stderr: #{follow_err}"

      follow_json = JSON.parse(follow_out)
      assert_equal "pass", follow_json["status"]
      assert_equal "ruby-holons", follow_json["response_sdk"]
    end
  end

  def test_echo_server_rejects_oversized_messages_and_stays_healthy
    with_ruby_echo_server("--listen", "tcp://127.0.0.1:0") do |uri|
      stdout, stderr, status = run_go_large_ping_probe(uri)
      assert status.success?, "oversized probe failed with stderr: #{stderr}"
      assert_match(/RESULT=RESOURCE_EXHAUSTED/, stdout)
      assert_match(/SMALL_OK/, stdout)
      assert_match(/SDK=ruby-holons/, stdout)
    end
  end

  private

  def sdk_dir
    File.expand_path("..", __dir__)
  end

  def sdk_root
    File.expand_path("../..", __dir__)
  end

  def go_holons_dir
    File.join(sdk_root, "go-holons")
  end

  def capture_forwarded_args(script, *script_args)
    Dir.mktmpdir("ruby-holons-fake-go") do |dir|
      args_file = File.join(dir, "args.txt")
      fake_go = File.join(dir, "go")

      File.write(fake_go, <<~SH)
        #!/usr/bin/env bash
        set -euo pipefail
        printf '%s\n' "$@" > "${FAKE_GO_ARGS_PATH}"
      SH
      File.chmod(0o755, fake_go)

      env = {
        "GO_BIN" => fake_go,
        "FAKE_GO_ARGS_PATH" => args_file,
        "GOCACHE" => "/tmp/go-cache-ruby-holons-tests"
      }
      _stdout, stderr, status =
        Open3.capture3(env, script, *script_args, chdir: sdk_dir)

      assert status.success?, "script failed with stderr: #{stderr}"
      File.readlines(args_file, chomp: true)
    end
  end

  def assert_flag_value(args, flag, expected)
    idx = args.index(flag)
    refute_nil idx, "missing flag #{flag} in #{args.inspect}"
    assert_equal expected, args[idx + 1]
  end

  def with_go_echo_server(listen_uri)
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }
    stdin, stdout, stderr, wait_thr = Open3.popen3(
      env,
      resolve_go_binary,
      "run",
      "./cmd/echo-server",
      "--listen",
      listen_uri,
      "--sdk",
      "go-holons",
      chdir: go_holons_dir
    )

    begin
      uri = nil
      Timeout.timeout(20) do
        uri = stdout.gets&.strip
      end
      if uri.nil? || uri.empty?
        error_output = stderr.read
        if bind_denied?(error_output)
          skip "Go echo-server requires local bind permissions in this environment"
        end
        raise "Go echo-server did not output URL: #{error_output}"
      end

      yield(uri)
    ensure
      stdin.close unless stdin.closed?
      begin
        Process.kill("TERM", wait_thr.pid)
      rescue StandardError
        nil
      end
      begin
        Timeout.timeout(5) { wait_thr.value }
      rescue StandardError
        begin
          Process.kill("KILL", wait_thr.pid)
        rescue StandardError
          nil
        end
      end
      stdout.close unless stdout.closed?
      stderr.close unless stderr.closed?
    end
  end

  def with_ruby_echo_server(*args)
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }
    script = File.join(sdk_dir, "bin", "echo-server")
    stdin, stdout, stderr, wait_thr = Open3.popen3(
      env,
      script,
      *args,
      chdir: sdk_dir
    )

    begin
      uri = nil
      Timeout.timeout(20) do
        uri = stdout.gets&.strip
      end
      if uri.nil? || uri.empty?
        error_output = stderr.read
        if bind_denied?(error_output)
          skip "ruby echo-server requires local bind permissions in this environment"
        end
        raise "ruby echo-server did not output URL: #{error_output}"
      end

      yield(uri)
    ensure
      stdin.close unless stdin.closed?
      begin
        Process.kill("TERM", wait_thr.pid)
      rescue StandardError
        nil
      end
      begin
        Timeout.timeout(5) { wait_thr.value }
      rescue StandardError
        begin
          Process.kill("KILL", wait_thr.pid)
        rescue StandardError
          nil
        end
      end
      stdout.close unless stdout.closed?
      stderr.close unless stderr.closed?
    end
  end

  def run_go_echo_client(*args)
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }
    Open3.capture3(
      env,
      resolve_go_binary,
      "run",
      "./cmd/echo-client",
      *args,
      chdir: go_holons_dir
    )
  end

  def run_go_large_ping_probe(uri)
    fixture = File.join(__dir__, "fixtures", "go_large_ping.go")
    helper = File.join(go_holons_dir, "tmp-ruby-large-ping-#{SecureRandom.uuid}.go")
    File.write(helper, File.read(fixture))
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }

    Open3.capture3(
      env,
      resolve_go_binary,
      "run",
      helper,
      uri,
      chdir: go_holons_dir
    )
  ensure
    File.delete(helper) if helper && File.exist?(helper)
  end

  def resolve_go_binary
    preferred = "/Users/bpds/go/go1.25.1/bin/go"
    File.executable?(preferred) ? preferred : "go"
  end

  def bind_denied?(text)
    normalized = text.to_s.downcase
    normalized.include?("bind: operation not permitted") ||
      normalized.include?("operation not permitted - bind")
  end
end

class HolonRPCTest < Minitest::Test
  def test_echo_roundtrip_with_go_helper
    with_go_helper("echo") do |url|
      client = Holons::HolonRPCClient.new(
        heartbeat_interval_ms: 250,
        heartbeat_timeout_ms: 250,
        reconnect_min_delay_ms: 100,
        reconnect_max_delay_ms: 400
      )

      client.connect(url)
      out = client.invoke("echo.v1.Echo/Ping", { "message" => "hello" })
      assert_equal "hello", out["message"]
      client.close
    end
  end

  def test_register_handles_server_calls
    with_go_helper("echo") do |url|
      client = Holons::HolonRPCClient.new(
        heartbeat_interval_ms: 250,
        heartbeat_timeout_ms: 250,
        reconnect_min_delay_ms: 100,
        reconnect_max_delay_ms: 400
      )

      client.register("client.v1.Client/Hello") do |params|
        { "message" => "hello #{params["name"] || ""}" }
      end

      client.connect(url)
      out = client.invoke("echo.v1.Echo/CallClient", {})
      assert_equal "hello go", out["message"]
      client.close
    end
  end

  def test_reconnect_and_heartbeat
    with_go_helper("drop-once") do |url|
      client = Holons::HolonRPCClient.new(
        heartbeat_interval_ms: 200,
        heartbeat_timeout_ms: 200,
        reconnect_min_delay_ms: 100,
        reconnect_max_delay_ms: 400
      )

      client.connect(url)
      first = client.invoke("echo.v1.Echo/Ping", { "message" => "first" })
      assert_equal "first", first["message"]

      sleep 0.7

      second = invoke_eventually(client, "echo.v1.Echo/Ping", { "message" => "second" })
      assert_equal "second", second["message"]

      hb = invoke_eventually(client, "echo.v1.Echo/HeartbeatCount", {})
      assert hb["count"].to_i >= 1
      client.close
    end
  end

  def test_ruby_holon_rpc_server_echo_roundtrip
    with_ruby_holon_rpc_server("ws://127.0.0.1:0/rpc") do |url|
      client = Holons::HolonRPCClient.new(
        heartbeat_interval_ms: 250,
        heartbeat_timeout_ms: 250,
        reconnect_min_delay_ms: 100,
        reconnect_max_delay_ms: 400
      )

      begin
        client.connect(url)
        out = client.invoke("echo.v1.Echo/Ping", { "message" => "ruby-server" })
        assert_equal "ruby-server", out["message"]
        assert_equal "ruby-holons", out["sdk"]
      ensure
        client.close
      end
    end
  end

  def test_ruby_holon_rpc_server_bidirectional_call
    with_ruby_holon_rpc_server("ws://127.0.0.1:0/rpc") do |url|
      client = Holons::HolonRPCClient.new(
        heartbeat_interval_ms: 250,
        heartbeat_timeout_ms: 250,
        reconnect_min_delay_ms: 100,
        reconnect_max_delay_ms: 400
      )

      client.register("client.v1.Client/Hello") do |params|
        { "message" => "hello #{params["name"] || ""}" }
      end

      begin
        client.connect(url)
        out = invoke_eventually(client, "echo.v1.Echo/CallClient", { "name" => "ruby" })
        assert_equal "hello ruby", out["message"]
      ensure
        client.close
      end
    end
  end

  private

  def invoke_eventually(client, method, params)
    last_error = nil
    40.times do
      begin
        return client.invoke(method, params)
      rescue StandardError => e
        last_error = e
        sleep 0.12
      end
    end
    raise(last_error || RuntimeError.new("invoke eventually failed"))
  end

  def with_go_helper(mode)
    sdk_dir = find_sdk_dir
    go_dir = File.join(sdk_dir, "go-holons")
    fixture = File.join(__dir__, "fixtures", "go_holonrpc_helper.go")
    helper = File.join(go_dir, "tmp-holonrpc-#{SecureRandom.uuid}.go")
    File.write(helper, File.read(fixture))

    go_bin = resolve_go_binary
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }
    stdin, stdout, stderr, wait_thr =
      Open3.popen3(env, go_bin, "run", helper, mode, chdir: go_dir)

    begin
      url = nil
      Timeout.timeout(20) do
        url = stdout.gets&.strip
      end
      if url.nil? || url.empty?
        error_output = stderr.read
        if bind_denied?(error_output)
          skip "Go helper requires local bind permissions in this environment"
        end
        raise "Go helper did not output URL: #{error_output}"
      end

      yield(url)
    ensure
      stdin.close unless stdin.closed?
      begin
        Process.kill("TERM", wait_thr.pid)
      rescue StandardError
        nil
      end
      begin
        Timeout.timeout(5) { wait_thr.value }
      rescue StandardError
        begin
          Process.kill("KILL", wait_thr.pid)
        rescue StandardError
          nil
        end
      end
      stdout.close unless stdout.closed?
      stderr.close unless stderr.closed?
      File.delete(helper) if File.exist?(helper)
    end
  end

  def with_ruby_holon_rpc_server(*args)
    sdk_dir = File.expand_path("..", __dir__)
    script = File.join(sdk_dir, "bin", "holon-rpc-server")
    env = {
      "GOCACHE" => ENV.fetch("GOCACHE", "/tmp/go-cache-ruby-holons-tests")
    }
    stdin, stdout, stderr, wait_thr =
      Open3.popen3(env, script, *args, chdir: sdk_dir)

    begin
      url = nil
      Timeout.timeout(20) do
        url = stdout.gets&.strip
      end
      if url.nil? || url.empty?
        error_output = stderr.read
        if bind_denied?(error_output)
          skip "ruby holon-rpc server requires local bind permissions in this environment"
        end
        raise "ruby holon-rpc server did not output URL: #{error_output}"
      end

      yield(url)
    ensure
      stdin.close unless stdin.closed?
      begin
        Process.kill("TERM", wait_thr.pid)
      rescue StandardError
        nil
      end
      begin
        Timeout.timeout(5) { wait_thr.value }
      rescue StandardError
        begin
          Process.kill("KILL", wait_thr.pid)
        rescue StandardError
          nil
        end
      end
      stdout.close unless stdout.closed?
      stderr.close unless stderr.closed?
    end
  end

  def find_sdk_dir
    dir = Dir.pwd
    12.times do
      candidate = File.join(dir, "go-holons")
      return dir if Dir.exist?(candidate)

      parent = File.dirname(dir)
      break if parent == dir

      dir = parent
    end
    raise "unable to locate sdk directory containing go-holons"
  end

  def resolve_go_binary
    preferred = "/Users/bpds/go/go1.25.1/bin/go"
    File.executable?(preferred) ? preferred : "go"
  end

  def bind_denied?(text)
    normalized = text.to_s.downcase
    normalized.include?("bind: operation not permitted") ||
      normalized.include?("operation not permitted - bind")
  end
end
