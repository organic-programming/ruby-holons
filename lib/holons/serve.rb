# frozen_string_literal: true

module Holons
  module Serve
    # Parse --listen or --port from args.
    def self.parse_flags(args)
      args.each_with_index do |arg, i|
        return args[i + 1] if arg == "--listen" && i + 1 < args.length
        return "tcp://:#{args[i + 1]}" if arg == "--port" && i + 1 < args.length
      end
      Transport::DEFAULT_URI
    end
  end
end
