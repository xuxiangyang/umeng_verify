require "umeng_verify/version"
require "umeng_verify/client"

module UmengVerify
  class Error < StandardError; end
  class ResponseError < Error
    attr_accessor :code, :request_id, :message
    def initialize(code, request_id, message)
      @code = code
      @request_id = request_id
      @message = message
      super("Bad Response with #{code}, message=#{message}")
    end
  end
end
