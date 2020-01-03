require 'securerandom'
require 'uri'
require 'digest'
require 'json'
require 'openssl'
require 'net/http'
require 'net/https'
require 'base64'
module UmengVerify
  class Client
    attr_accessor :app_secret, :app_key, :host, :http
    def initialize(app_key, app_secret)
      @app_secret = app_secret
      @app_key = app_key
      @host = "verify5.market.alicloudapi.com"
      @http = Net::HTTP.new(@host, 443)
      @http.use_ssl = true
    end

    def info(token)
      request("POST", "/api/v1/mobile/info", token: token)
    end

    def verify(token, phone_number)
      request("POST", "/api/v1/mobile/verify", token: token, phoneNumber: phone_number)
    end

    def request(method, path, body = {}, headers = {})
      headers["Content-Type"] = "application/json; charset=UTF-8"
      headers["Accept"] = "application/json"
      headers["Content-MD5"] = Base64.strict_encode64(Digest::MD5.digest(JSON.dump(body)))
      headers["Date"] = Time.now.gmtime.strftime("%a, %d %b %Y %H:%M:%S GMT")
      headers["X-Ca-Version"] = "1"
      headers["X-Ca-Stage"] = "RELEASE"
      headers["X-Ca-Key"] = app_key
      headers["X-Ca-Timestamp"] = (Time.now.to_f * 1000).to_i.to_s
      headers["X-Ca-Nonce"] = SecureRandom.hex

      query = URI(path).query
      form = query ? URI.decode_www_form(query).to_h : {}

      signature_headers = ["X-Ca-Version", "X-Ca-Stage", "X-Ca-Key", "X-Ca-Timestamp", "X-Ca-Nonce"].sort

      string_to_sign = [
        method,
        headers["Accept"],
        headers["Content-MD5"],
        headers["Content-Type"],
        headers["Date"],
        signature_headers.map { |k| "#{k}:#{headers[k]}" }.join("\n"),
        form.empty? ? path : "#{path}?#{form.sort.map { |k, v| "#{k}=#{v}" }.join('&')}",
      ].join("\n")

      headers["X-Ca-Signature"] = Base64.strict_encode64(OpenSSL::HMAC.digest("SHA256", app_secret, string_to_sign))
      headers["X-Ca-Signature-Headers"] = signature_headers.join(",")

      if method == Net::HTTP::Get::METHOD
        request = Net::HTTP::Get.new(path, headers)
      else
        request = Net::HTTP::Post.new(path, headers)
        request.body = JSON.dump(body)
      end

      resp = http.request(request)
      raise ResponseError.new(resp.code.to_i, resp["X-Ca-Request-Id"], resp["X-Ca-Error-Message"]) unless resp.code.to_i == 200

      JSON.parse(resp.body)
    end
  end
end
