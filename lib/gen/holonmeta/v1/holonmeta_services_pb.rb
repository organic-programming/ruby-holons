# frozen_string_literal: true
# Generated from holonmeta/v1/holonmeta.proto.

require "grpc"
require_relative "holonmeta_pb"

module Holonmeta
  module V1
    module HolonMeta
      class Service
        include ::GRPC::GenericService

        self.marshal_class_method = :encode
        self.unmarshal_class_method = :decode
        self.service_name = "holonmeta.v1.HolonMeta"

        rpc :Describe, ::Holonmeta::V1::DescribeRequest, ::Holonmeta::V1::DescribeResponse
      end

      Stub = Service.rpc_stub_class
    end
  end
end
