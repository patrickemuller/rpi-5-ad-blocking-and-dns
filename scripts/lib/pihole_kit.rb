# frozen_string_literal: true

# Shared helpers for pihole_tool.rb and pihole_bench.rb: Pi-hole v6 API client, a tiny DNS client,
# settings-profile handling and blocklist parsing. Ruby >= 3.1, standard library only.

require "io/console"
require "ipaddr"
require "json"
require "net/http"
require "open3"
require "openssl"
require "socket"
require "uri"

module PiholeKit
  ROOT = File.expand_path("../..", __dir__)
  DEFAULT_PROFILE = File.join(ROOT, "config", "recommended.json")
  DEFAULT_LOCAL = File.join(ROOT, "config", "settings.local.json")
  BACKUP_DIR = File.join(ROOT, "backups")

  # Upstream resolver IPs grouped by operator; used to flag mixed-provider setups.
  PROVIDERS = {
    "Cloudflare" => ["1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "2606:4700:4700::"],
    "Google" => ["8.8.8.8", "8.8.4.4", "2001:4860:4860::"],
    "Quad9" => ["9.9.9.", "149.112.112.", "2620:fe::"],
    "OpenDNS" => ["208.67.222.", "208.67.220.", "2620:119:"],
    "AdGuard" => ["94.140.14.", "94.140.15.", "2a10:50c0::"],
    "Mullvad" => ["194.242.2.", "2a07:e340::"],
    "DNS4EU" => ["86.54.11.", "2a13:1001::"]
  }.freeze

  LIST_STATUS = { 1 => "downloaded", 2 => "unchanged", 3 => "unavailable, using cached copy",
                  4 => "unavailable, no local copy" }.freeze
  HAGEZI_RE = %r{hagezi.*/(light|multi|pro|pro\.plus|ultimate|tif|tif\.medium|tif\.mini|fake|popupads|native\.[a-z]+)(?:-onlydomains|-compressed)?\.txt\z}
  HAGEZI_MAIN = %w[light multi pro pro.plus ultimate].freeze

  module_function

  def die(msg, code = 1)
    warn "error: #{msg}"
    exit code
  end

  def fmt(value)
    value.is_a?(String) ? "'#{value}'" : JSON.generate(value)
  end

  def getpass(prompt)
    return nil unless $stdin.tty?

    $stderr.print prompt
    pw = $stdin.noecho(&:gets)&.chomp
    $stderr.puts
    pw
  end

  # Run the block for every item on `threads` threads; returns results in input order.
  def parallel_map(items, threads)
    queue = Queue.new
    items.each_with_index { |item, i| queue << [item, i] }
    results = Array.new(items.size)
    Array.new([threads, items.size].min) do
      Thread.new do
        loop do
          item, i = queue.pop(true)
          results[i] = yield(item)
        rescue ThreadError
          break
        end
      end
    end.each(&:join)
    results
  end

  def pct(values, q)
    return nil if values.empty?

    v = values.sort
    v[[v.size - 1, ((v.size - 1) * q).round].min]
  end

  def provider_of(server)
    ip = server.split("#").first
    return "local resolver (e.g. unbound)" if ip.start_with?("127.") || ip == "::1"

    begin
      return "private #{ip}" if IPAddr.new(ip).private?
    rescue IPAddr::InvalidAddressError
      return ip
    end
    PROVIDERS.each { |name, prefixes| return name if prefixes.any? { |p| ip.start_with?(p) } }
    ip
  end

  # ------------------------------------------------------------------------- API client

  class ApiError < StandardError
    attr_reader :status

    def initialize(status, message)
      @status = status
      super(status.positive? ? "HTTP #{status}: #{message}" : message)
    end
  end

  class Client
    attr_reader :base
    attr_accessor :sid

    def initialize(url, insecure: false)
      @base = url.chomp("/").delete_suffix("/admin")
      @insecure = insecure
      @sid = nil
    end

    def host
      URI(@base).hostname.to_s
    end

    def request(method, path, body: nil, raw: false, timeout: 30)
      uri = URI("#{@base}/api/#{path.delete_prefix('/')}")
      klass = { "GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post, "PATCH" => Net::HTTP::Patch,
                "PUT" => Net::HTTP::Put, "DELETE" => Net::HTTP::Delete }.fetch(method)
      req = klass.new(uri)
      req["Accept"] = "application/json"
      req["sid"] = @sid if @sid
      if body
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(body)
      end
      resp = http_for(uri, timeout).request(req)
      code = resp.code.to_i
      if [301, 302, 307, 308].include?(code) && resp["location"].to_s.start_with?("https://") && @base.start_with?("http://")
        switch_to_https(resp["location"])
        return request(method, path, body: body, raw: raw, timeout: timeout)
      end
      raise ApiError.new(code, error_message(resp.body)) if code >= 400
      return [resp.body, resp] if raw

      resp.body.to_s.empty? ? {} : JSON.parse(resp.body)
    rescue OpenSSL::SSL::SSLError => e
      if e.message.match?(/certificate verify failed|hostname|does not match/i)
        raise ApiError.new(0, "Pi-hole's HTTPS certificate is self-signed: re-run with --insecure, or set " \
                              "webserver.port back to the default (no HTTP→HTTPS redirect) and use http://.")
      end

      raise ApiError.new(0, "TLS error talking to #{uri}: #{e.message}")
    rescue SystemCallError, IOError, SocketError, Net::OpenTimeout, Net::ReadTimeout => e
      raise ApiError.new(0, "cannot reach #{uri}: #{e.message}")
    end

    def password_set?
      r = request("GET", "auth")
      s = r.fetch("session", {})
      !(s["valid"] && s["sid"].nil?)
    rescue ApiError => e
      return true if e.status == 401

      raise
    end

    def login(password, totp = nil)
      body = { "password" => password }
      body["totp"] = Integer(totp) if totp && !totp.empty?
      s = request("POST", "auth", body: body).fetch("session", {})
      raise ApiError.new(401, s["message"] || "login failed") unless s["valid"]

      @sid = s["sid"]
    end

    def logout
      return unless @sid

      begin
        request("DELETE", "auth")
      rescue ApiError
        nil
      end
      @sid = nil
    end

    private

    def http_for(uri, timeout)
      http = Net::HTTP.new(uri.hostname, uri.port)
      http.open_timeout = [timeout, 10].min
      http.read_timeout = timeout
      if uri.scheme == "https"
        http.use_ssl = true
        http.verify_mode = @insecure ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      end
      http
    end

    def error_message(body)
      data = JSON.parse(body.to_s)
      return data["session"]["message"] || "unauthorized" if data["session"]

      err = data.fetch("error")
      "#{err['key']}: #{err['message']}#{err['hint'] ? " (#{err['hint']})" : ''}"
    rescue JSON::ParserError, KeyError, TypeError, NoMethodError
      body.to_s[0, 200]
    end

    # Follow an HTTP->HTTPS redirect but keep the host we were given: the Location header uses
    # webserver.domain (pi.hole by default), which clients often can't resolve.
    def switch_to_https(location)
      h = host.include?(":") ? "[#{host}]" : host
      port = URI(location).port
      @base = "https://#{h}#{port && port != 443 ? ":#{port}" : ''}"
      warn "  note: web server redirects HTTP to HTTPS, continuing with #{@base}"
    end
  end

  # Returns [client, password_set?]. Logs in when a password is set and auth is required.
  def connect(opts, require_auth: true)
    ph = Client.new(opts[:url], insecure: opts[:insecure])
    begin
      has_pw = ph.password_set?
    rescue ApiError => e
      die(e.message)
    end
    if has_pw && require_auth
      password = ENV["PIHOLE_PASSWORD"]
      if password.to_s.empty?
        die("Pi-hole has a password; set PIHOLE_PASSWORD (an app password works).") unless $stdin.tty?
        password = getpass("Pi-hole password (or app password): ")
      end
      begin
        ph.login(password, ENV["PIHOLE_TOTP"])
      rescue ApiError => e
        raise unless e.message.downcase.include?("totp") && $stdin.tty?

        $stderr.print "2FA code: "
        ph.login(password, $stdin.gets.to_s.strip)
      end
    end
    [ph, has_pw]
  rescue ApiError => e
    die(e.message)
  end

  # ------------------------------------------------------------------------- config helpers

  def flatten(hash, prefix = "")
    hash.each_with_object({}) do |(k, v), out|
      key = "#{prefix}#{k}"
      v.is_a?(Hash) ? out.merge!(flatten(v, "#{key}.")) : out[key] = v
    end
  end

  # /api/config?detailed=true wraps each leaf in {value, default, description, allowed, ...}.
  def flatten_detailed(hash, prefix = "")
    hash.each_with_object({}) do |(k, v), out|
      key = "#{prefix}#{k}"
      next unless v.is_a?(Hash)

      v.key?("value") && v.key?("description") ? out[key] = v : out.merge!(flatten_detailed(v, "#{key}."))
    end
  end

  def nest(flat)
    flat.each_with_object({}) do |(key, value), out|
      *parents, leaf = key.split(".")
      node = parents.reduce(out) { |n, p| n[p] ||= {} }
      node[leaf] = value
    end
  end

  def load_local(path)
    return {} unless File.file?(path) && !File.read(path).strip.empty?

    JSON.parse(File.read(path))
  rescue JSON::ParserError => e
    die("#{path}: invalid JSON (#{e.message})")
  end

  # Generic profile merged with local overrides -> {key => {"value", "apply", "why", "ui", "source"}}.
  def load_profile(profile_path, local)
    profile = JSON.parse(File.read(profile_path)).fetch("settings")
    merged = profile.transform_values { |v| v.merge("source" => "profile") }
    local.fetch("settings", {}).each do |key, value|
      entry = merged[key] ||= { "apply" => true, "why" => "local override", "ui" => "Settings → All settings" }
      entry["value"] = value
      entry["source"] = "local"
    end
    merged
  rescue SystemCallError, JSON::ParserError, KeyError => e
    die("cannot load profile #{profile_path}: #{e.message}")
  end

  # Pi-hole/civetweb ACL: empty = allow all, otherwise deny unless the LAST matching rule is '+'.
  def acl_allows?(acl, ip)
    return true if acl.strip.empty?

    addr = IPAddr.new(ip.split("%").first)
    allowed = false
    acl.split(",").map(&:strip).reject(&:empty?).each do |rule|
      net = IPAddr.new(rule[1..].delete("[]"))
      allowed = rule.start_with?("+") if net.family == addr.family && net.include?(addr)
    rescue IPAddr::InvalidAddressError
      next
    end
    allowed
  end

  # ------------------------------------------------------------------------- tiny DNS client

  RCODES = { 0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED" }.freeze
  BLOCK_EDE = [15, 16, 17].freeze # Extended DNS Error: Blocked, Censored, Filtered (Pi-hole sends 15)

  # A recursive A/AAAA query with EDNS0 (1232-byte buffer) and the AD bit set to ask for validation status.
  def build_query(name, qtype = 1)
    header = [rand(65_536), 0x0120, 1, 0, 0, 1].pack("n6")
    qname = name.chomp(".").split(".").map { |label| [label.bytesize].pack("C") + label.b }.join + "\x00".b
    header + qname + [qtype, 1].pack("n2") + "\x00".b + [41, 1232, 0, 0].pack("nnNn")
  end

  # 'ip', 'ip#port' or hostname -> Addrinfo for UDP.
  def resolve_server(server)
    host, port = server.split("#", 2)
    Addrinfo.getaddrinfo(host, Integer(port || 53), nil, :DGRAM).first
  end

  def skip_name(buf, off)
    loop do
      len = buf.getbyte(off)
      return off + 1 if len.zero?
      return off + 2 if (len & 0xC0) == 0xC0

      off += 1 + len
    end
  end

  # -> {"rcode", "answers" (A/AAAA), "ad", "ede" (Extended DNS Error code or nil)}
  def parse_response(buf)
    flags, qd, an, ns, ar = buf.byteslice(2, 10).unpack("n5")
    off = 12
    qd.times { off = skip_name(buf, off) + 4 }
    answers = []
    ede = nil
    (an + ns + ar).times do |i|
      off = skip_name(buf, off)
      rtype, _cls, _ttl, rdlen = buf.byteslice(off, 10).unpack("nnNn")
      off += 10
      rdata = buf.byteslice(off, rdlen)
      off += rdlen
      if i < an && ((rtype == 1 && rdlen == 4) || (rtype == 28 && rdlen == 16))
        answers << IPAddr.new_ntoh(rdata).to_s
      elsif rtype == 41 # OPT: walk the EDNS options looking for EDE (code 15)
        o = 0
        while o + 4 <= rdata.bytesize
          code, olen = rdata.byteslice(o, 4).unpack("n2")
          ede = rdata.byteslice(o + 4, 2).unpack1("n") if code == 15 && olen >= 2
          o += 4 + olen
        end
      end
    end
    { "rcode" => RCODES.fetch(flags & 0xF, (flags & 0xF).to_s), "answers" => answers,
      "ad" => (flags & 0x20) != 0, "ede" => ede }
  end

  # One UDP query to an Addrinfo. Returns [milliseconds or nil on timeout, response hash].
  def timed_query(addrinfo, name, timeout: 2.0)
    packet = build_query(name)
    sock = Socket.new(addrinfo.afamily, :DGRAM)
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    deadline = start + timeout
    sock.send(packet, 0, addrinfo)
    loop do
      left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return [nil, { "error" => "timeout" }] if left <= 0 || IO.select([sock], nil, nil, left).nil?

      buf = sock.recv(4096)
      next unless buf.byteslice(0, 2) == packet.byteslice(0, 2)

      ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000
      return [ms, parse_response(buf)]
    end
  rescue SystemCallError, SocketError => e
    [nil, { "error" => e.message }]
  ensure
    sock&.close
  end

  def dns_query(server, name, timeout: 3.0)
    timed_query(resolve_server(server), name, timeout: timeout).last
  rescue SocketError => e
    { "error" => e.message }
  end

  # Lenient: Pi-hole block (EDE or null address) or NXDOMAIN, as any filtering resolver would answer.
  def blocked_answer?(r)
    return true if BLOCK_EDE.include?(r["ede"]) || r["rcode"] == "NXDOMAIN"

    r["rcode"] == "NOERROR" && r.fetch("answers", []).all? { |a| ["0.0.0.0", "::"].include?(a) }
  end

  # Strict: Pi-hole's own block answer (EDE 15 or a null address), not an upstream NXDOMAIN.
  def pihole_blocked?(r)
    return true if BLOCK_EDE.include?(r["ede"])

    ans = r.fetch("answers", [])
    r["rcode"] == "NOERROR" && !ans.empty? && ans.all? { |a| ["0.0.0.0", "::"].include?(a) }
  end

  # ------------------------------------------------------------------------- blocklists

  def fetch_text(url)
    uri = URI(url)
    10.times do
      resp = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https", open_timeout: 20,
                                                     read_timeout: 120) do |http|
        http.request(Net::HTTP::Get.new(uri, "User-Agent" => "pihole-tool/1.0"))
      end
      return resp.body.to_s.dup.force_encoding("UTF-8").scrub unless resp.is_a?(Net::HTTPRedirection)

      uri = URI.join(uri, resp["location"])
    end
    raise "too many redirects for #{url}"
  end

  # [exact, wildcard] domain sets the way Pi-hole reads them: hosts/plain lines are exact,
  # Adblock `||domain^` lines also cover subdomains.
  def parse_list(text)
    exact = {}
    wild = {}
    text.each_line do |line|
      line = line.strip
      next if line.empty? || "#![".include?(line[0]) || line.start_with?("@@")

      if line.start_with?("||")
        d = line[2..].split("^").first.to_s.downcase
        wild[d] = true unless d.empty? || d.include?("*") || d.include?("/")
        next
      end
      parts = line.split("#").first.to_s.split
      next if parts.empty?

      d = (parts.size > 1 && ["0.0.0.0", "127.0.0.1", "::", "::1"].include?(parts[0]) ? parts[1] : parts[0]).downcase
      exact[d] = true if d.include?(".") && !["0.0.0.0", "localhost.localdomain", "broadcasthost"].include?(d)
    end
    [exact, wild]
  end

  def covered?(domain, exact, wild)
    return true if exact.key?(domain)

    labels = domain.split(".")
    (0...(labels.size - 1)).any? { |i| wild.key?(labels[i..].join(".")) }
  end
end
