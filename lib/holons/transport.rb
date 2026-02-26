# frozen_string_literal: true

require "socket"

module Holons
  module Transport
    DEFAULT_URI = "tcp://:9090"

    ParsedURI = Struct.new(:raw, :scheme, :host, :port, :path, :secure, keyword_init: true)

    module Listener
      Tcp = Struct.new(:socket)
      Unix = Struct.new(:socket, :path)
      Stdio = Struct.new(:address, :consumed)
      Mem = Struct.new(:address, :server_io, :client_io, :server_consumed, :client_consumed)
      WS = Struct.new(:host, :port, :path, :secure, keyword_init: true)
    end

    Connection = Struct.new(:reader, :writer, :scheme, :owns_reader, :owns_writer)

    # Extract scheme from a transport URI.
    def self.scheme(uri)
      idx = uri.index("://")
      idx ? uri[0...idx] : uri
    end

    # Parse a transport URI into a normalized structure.
    def self.parse_uri(uri)
      s = scheme(uri)

      case s
      when "tcp"
        raise ArgumentError, "invalid tcp URI: #{uri}" unless uri.start_with?("tcp://")

        host, port = split_host_port(uri.delete_prefix("tcp://"), 9090)
        ParsedURI.new(raw: uri, scheme: "tcp", host: host, port: port, path: nil, secure: false)
      when "unix"
        raise ArgumentError, "invalid unix URI: #{uri}" unless uri.start_with?("unix://")

        path = uri.delete_prefix("unix://")
        raise ArgumentError, "invalid unix URI: #{uri}" if path.empty?

        ParsedURI.new(raw: uri, scheme: "unix", host: nil, port: nil, path: path, secure: false)
      when "stdio"
        ParsedURI.new(raw: "stdio://", scheme: "stdio", host: nil, port: nil, path: nil, secure: false)
      when "mem"
        raw = uri.start_with?("mem://") ? uri : "mem://"
        name = raw.delete_prefix("mem://")
        ParsedURI.new(raw: raw, scheme: "mem", host: nil, port: nil, path: name, secure: false)
      when "ws", "wss"
        secure = s == "wss"
        prefix = secure ? "wss://" : "ws://"
        raise ArgumentError, "invalid ws URI: #{uri}" unless uri.start_with?(prefix)

        trimmed = uri.delete_prefix(prefix)
        addr, path = trimmed.split("/", 2)
        path = path.nil? || path.empty? ? "/grpc" : "/#{path}"
        host, port = split_host_port(addr, secure ? 443 : 80)
        ParsedURI.new(raw: uri, scheme: s, host: host, port: port, path: path, secure: secure)
      else
        raise ArgumentError, "unsupported transport URI: #{uri}"
      end
    end

    # Parse a transport URI and return a listener variant.
    def self.listen(uri)
      parsed = parse_uri(uri)

      case parsed.scheme
      when "tcp"
        Listener::Tcp.new(listen_tcp(parsed))
      when "unix"
        Listener::Unix.new(listen_unix(parsed.path), parsed.path)
      when "stdio"
        Listener::Stdio.new("stdio://", false)
      when "mem"
        server_io, client_io = Socket.pair(:UNIX, :STREAM, 0)
        Listener::Mem.new(parsed.raw || "mem://", server_io, client_io, false, false)
      when "ws", "wss"
        Listener::WS.new(
          host: parsed.host || "0.0.0.0",
          port: parsed.port || (parsed.secure ? 443 : 80),
          path: parsed.path || "/grpc",
          secure: parsed.secure
        )
      else
        raise ArgumentError, "unsupported transport URI: #{uri}"
      end
    end

    # Accept one runtime connection from a listener.
    def self.accept(listener)
      case listener
      when Listener::Tcp
        socket = listener.socket.accept
        Connection.new(socket, socket, "tcp", true, true)
      when Listener::Unix
        socket = listener.socket.accept
        Connection.new(socket, socket, "unix", true, true)
      when Listener::Stdio
        raise RuntimeError, "stdio:// accepts exactly one connection" if listener.consumed

        listener.consumed = true
        Connection.new($stdin, $stdout, "stdio", false, false)
      when Listener::Mem
        raise RuntimeError, "mem:// server side already consumed" if listener.server_consumed || listener.server_io.nil?

        io = listener.server_io
        listener.server_io = nil
        listener.server_consumed = true
        Connection.new(io, io, "mem", true, true)
      when Listener::WS
        raise RuntimeError, "ws/wss runtime accept is unsupported (metadata-only listener)"
      else
        raise RuntimeError, "unsupported listener type"
      end
    end

    # Dial the client side of a mem:// listener.
    def self.mem_dial(listener)
      unless listener.is_a?(Listener::Mem)
        raise ArgumentError, "mem_dial requires a mem:// listener"
      end

      if listener.client_consumed || listener.client_io.nil?
        raise RuntimeError, "mem:// client side already consumed"
      end

      io = listener.client_io
      listener.client_io = nil
      listener.client_consumed = true
      Connection.new(io, io, "mem", true, true)
    end

    def self.conn_read(connection, max_bytes = 4096)
      connection.reader.readpartial(max_bytes)
    rescue EOFError
      ""
    end

    def self.conn_write(connection, data)
      payload = data.is_a?(String) ? data : data.to_s
      connection.writer.write(payload)
      connection.writer.flush if connection.writer.respond_to?(:flush)
      payload.bytesize
    end

    def self.close_connection(connection)
      if connection.owns_reader && connection.reader.respond_to?(:close) && !connection.reader.closed?
        connection.reader.close
      end
      if connection.owns_writer && connection.writer != connection.reader &&
         connection.writer.respond_to?(:close) && !connection.writer.closed?
        connection.writer.close
      end
    end

    def self.listen_tcp(parsed)
      host = parsed.host || "0.0.0.0"
      port = parsed.port || 9090
      TCPServer.new(host, port)
    end

    def self.listen_unix(path)
      File.delete(path) if File.exist?(path)
      UNIXServer.new(path)
    end

    def self.split_host_port(addr, default_port)
      return ["0.0.0.0", default_port] if addr.empty?

      host, separator, port_text = addr.rpartition(":")
      return [addr, default_port] if separator.empty?

      host = "0.0.0.0" if host.empty?
      port = port_text.empty? ? default_port : Integer(port_text, 10)
      [host, port]
    end

    private_class_method :listen_tcp, :listen_unix, :split_host_port
  end
end
