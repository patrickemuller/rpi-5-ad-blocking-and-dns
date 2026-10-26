#!/usr/bin/env ruby
# frozen_string_literal: true

# Audit a Pi-hole v6 install and apply a recommended settings profile.
#
# Ruby >= 3.1, standard library only (on the Pi: `sudo apt install ruby`).
#
#   ruby scripts/pihole_tool.rb audit                 # read-only health/security report
#   ruby scripts/pihole_tool.rb apply                 # show what would change (dry run)
#   ruby scripts/pihole_tool.rb apply --yes           # back up, apply, verify
#   ruby scripts/pihole_tool.rb set-password
#   ruby scripts/pihole_tool.rb backup
#   ruby scripts/pihole_tool.rb lists show|overlap|usage|disable|enable
#   ruby scripts/pihole_tool.rb gravity
#
# Connection: --url / $PIHOLE_URL / "url" in config/settings.local.json (default http://pi.hole).
# Password:   $PIHOLE_PASSWORD (an app password works too), otherwise prompted when needed.

require "optparse"
require_relative "lib/pihole_kit"

module PiholeTool
  K = PiholeKit

  # Ports worth knowing about on a DNS appliance. Anything besides DNS + web UI is extra attack surface.
  COMMON_PORTS = {
    21 => "ftp", 22 => "ssh", 23 => "telnet", 53 => "dns", 80 => "http (Pi-hole UI)", 139 => "smb",
    443 => "https (Pi-hole UI)", 445 => "smb", 1883 => "mqtt", 3000 => "web app", 3389 => "rdp", 5000 => "web app",
    5335 => "unbound (should be localhost only)", 5900 => "vnc", 8000 => "web app", 8080 => "web app",
    8081 => "web app", 8096 => "jellyfin/emby", 8112 => "deluge", 8123 => "home assistant", 8443 => "web app",
    8920 => "jellyfin/emby https", 9000 => "portainer", 9090 => "cockpit / web app", 9443 => "portainer", 32400 => "plex"
  }.freeze

  class Report
    def initialize
      @counts = Hash.new(0)
    end

    def section(title)
      puts "\n== #{title}"
    end

    def line(level, msg)
      @counts[level] += 1
      puts format("  [%-6s] %s", level, msg)
    end

    def summary
      parts = %w[CRIT WARN REVIEW OK].select { |k| @counts[k].positive? }.map { |k| "#{@counts[k]} #{k}" }
      puts "\nSummary: #{parts.join(', ')}"
      return 2 if @counts["CRIT"].positive?

      @counts["WARN"].positive? ? 1 : 0
    end
  end

  module_function

  # ------------------------------------------------------------------------- client-side discovery

  def valid_unicast(token)
    token = token.split("#").first
    ip = IPAddr.new(token.split("%").first)
    return nil if ip.to_s == "127.0.0.53" || ip.to_s == "0.0.0.0" || ip.to_s == "::" ||
                  IPAddr.new(ip.ipv4? ? "224.0.0.0/4" : "ff00::/8").include?(ip)

    token
  rescue IPAddr::InvalidAddressError
    nil
  end

  def run_cmd(*cmd)
    out, = Open3.capture3(*cmd)
    out
  rescue SystemCallError
    ""
  end

  def which(cmd)
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? { |d| File.executable?(File.join(d, cmd)) }
  end

  # [DNS servers this machine currently uses, where they came from]
  def client_dns_servers
    found = []
    source = ""
    if RUBY_PLATFORM.include?("darwin") && which("scutil")
      source = "scutil --dns"
      found = run_cmd("scutil", "--dns").scan(/nameserver\[\d+\]\s*:\s*(\S+)/).flatten
    elsif RUBY_PLATFORM.include?("linux")
      if which("resolvectl")
        source = "resolvectl dns"
        run_cmd("resolvectl", "dns").each_line { |l| found.concat(l.split(":", 2)[1].to_s.split) if l.include?(":") }
      end
      if found.none? { |t| valid_unicast(t) } && File.exist?("/etc/resolv.conf")
        source = "/etc/resolv.conf"
        found = File.read("/etc/resolv.conf").scan(/^\s*nameserver\s+(\S+)/).flatten
      end
    end
    [found.filter_map { |t| valid_unicast(t) }.uniq, source]
  end

  def probe_ports(host, ports)
    open = K.parallel_map(ports.keys, 32) do |port|
      Socket.tcp(host, port, connect_timeout: 0.6, &:close)
      port
    rescue SystemCallError, SocketError, IOError
      nil
    end
    open.compact.sort
  end

  def ssh_auth_methods(host)
    return [] unless which("ssh")

    _, err, = Open3.capture3("ssh", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
                             "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
                             "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                             "pihole-audit@#{host}", "true")
    m = err.match(/Permission denied \(([^)]*)\)/)
    m ? m[1].split(",") : []
  rescue SystemCallError
    []
  end

  # ------------------------------------------------------------------------- audit

  def cmd_audit(opts)
    rep = Report.new
    profile = K.load_profile(opts[:profile], K.load_local(opts[:local]))
    ph = K::Client.new(opts[:url], insecure: opts[:insecure])

    rep.section("Connection and authentication (#{ph.base})")
    begin
      login_info = ph.request("GET", "info/login")
      has_pw = ph.password_set?
    rescue K::ApiError => e
      K.die(e.message)
    end
    rep.line("OK", "API reachable, DNS running: #{login_info['dns']}")
    authed = true
    if has_pw
      rep.line("OK", "Admin password is set")
      password = ENV["PIHOLE_PASSWORD"]
      password = K.getpass("Pi-hole password (or app password, empty = skip authenticated checks): ") if password.to_s.empty?
      if password.to_s.empty?
        authed = false
        rep.line("INFO", "No password given: skipping checks that need the API")
      else
        begin
          ph.login(password, ENV["PIHOLE_TOTP"])
        rescue K::ApiError => e
          rep.line("WARN", "login failed (#{e.message}); running unauthenticated checks only")
          authed = false
        end
      end

    else
      rep.line("CRIT", "No admin password: anyone on the network can change settings or disable blocking " \
                       "through the web UI/API. Fix: sudo pihole setpassword (or `pihole_tool.rb set-password`).")
    end

    begin
      audit_api(ph, rep, profile, has_pw) if authed
      audit_client(ph, rep, opts[:test_domain]) unless opts[:no_client_checks]
      audit_host(ph, rep) unless opts[:no_port_scan]
    ensure
      ph.logout
    end
    rep.summary
  end

  def audit_api(ph, rep, profile, has_pw)
    rep.section("Versions")
    versions = ph.request("GET", "info/version")["version"]
    %w[core web ftl docker].each do |comp|
      info = versions[comp] || {}
      loc = info["local"].is_a?(Hash) ? info["local"] : { "version" => info["local"] }
      rem = info["remote"].is_a?(Hash) ? info["remote"] : { "version" => info["remote"] }
      lv = loc["version"]
      rv = rem["version"]
      next unless lv

      if rv && lv != rv
        rep.line("WARN", "#{comp}: #{lv} installed, #{rv} available. Read the release notes, back up, then " \
                         "`pihole -up` (Docker: pull the new image).")
      else
        rep.line("OK", "#{comp}: #{lv} (latest)")
      end
    end

    rep.section("Settings vs profile")
    detailed = K.flatten_detailed(ph.request("GET", "config?detailed=true")["config"])
    profile.each do |key, entry|
      unless detailed.key?(key)
        rep.line("INFO", "#{key}: not present in this Pi-hole version")
        next
      end
      current = detailed[key]["value"]
      default = detailed[key]["default"]
      want = entry["value"]
      tag = "#{key} = #{K.fmt(current)}"
      if want.nil?
        rep.line("REVIEW", "#{tag}  (network-specific: set it in config/settings.local.json) #{entry['why']}")
      elsif current == want
        rep.line("OK", tag)
      elsif entry.fetch("apply", true) == false
        rep.line("REVIEW", "#{tag}, profile suggests #{K.fmt(want)}: #{entry['why']}")
      else
        src = entry["source"] == "local" ? " [local]" : ""
        rep.line("WARN", "#{tag} → recommended #{K.fmt(want)}#{src} (default #{K.fmt(default)}): #{entry['why']}")
      end
    end
    api = K.flatten(ph.request("GET", "config/webserver/api")["config"])
    if has_pw && api["webserver.api.app_pwhash"].to_s.empty?
      rep.line("INFO", "No app password configured: create one for scripts/integrations " \
                       "(Settings → Web interface / API → Configure app password)")
    end

    rep.section("Upstream DNS servers")
    upstreams = detailed.dig("dns.upstreams", "value") || []
    providers = upstreams.map { |u| K.provider_of(u) }.uniq
    rep.line("INFO", "#{upstreams.size} configured: #{upstreams.empty? ? '(none)' : upstreams.join(', ')}")
    if providers.size > 1
      rep.line("WARN", "Mixed providers (#{providers.join(', ')}): answers, filtering and logging policies differ " \
                       "between them. Pick one provider pair (or a local recursive resolver).")
    end
    begin
      ph.request("GET", "stats/upstreams")["upstreams"].each do |u|
        next unless u.fetch("port", -1).positive? && u["count"].to_i.positive?

        rep.line("INFO", format("  %-18s %7d queries, mean %.1f ms", u["ip"], u["count"], u["statistics"]["response"] * 1000))
      end
    rescue K::ApiError, NoMethodError
      nil
    end
    unless detailed.dig("dns.dnssec", "value")
      r = K.dns_query(ph.host, "dnssec-failed.org")
      if r["rcode"] == "SERVFAIL"
        rep.line("OK", "DNSSEC: broken-signature test domain fails (validated upstream; dns.dnssec can stay off)")
      elsif !r.key?("error")
        rep.line("WARN", "DNSSEC: dnssec-failed.org resolves → nothing in the chain validates. " \
                         "Use validating upstreams or enable dns.dnssec.")
      end
    end

    rep.section("Runtime health")
    q = ph.request("GET", "stats/summary")["queries"]
    total = q["total"].to_i
    if total.positive?
      rep.line("INFO", format("Queries (24h): %d, blocked %.1f%%, answered from cache %.0f%%, forwarded %.0f%%",
                              total, q["percent_blocked"], 100.0 * q["cached"] / total, 100.0 * q["forwarded"] / total))
    end
    ftl = ph.request("GET", "info/ftl")["ftl"]
    freed = ftl.dig("dnsmasq", "dns_cache_live_freed").to_i
    if freed.positive?
      rep.line("REVIEW", "Cache evicted #{freed} live entries: dns.cache.size could be raised a little")
    else
      rep.line("OK", "Cache never evicted a live entry: dns.cache.size is big enough (don't raise it)")
    end
    system = ph.request("GET", "info/system")["system"]
    load = system["cpu"]["load"]["raw"]
    rep.line("INFO", format("Load %.2f/%.2f/%.2f on %d cores, RAM used %.0f%%", *load, system["cpu"]["nprocs"],
                            system["memory"]["ram"]["%used"]))
    begin
      ph.request("GET", "info/sensors")["sensors"]["list"].each do |s|
        s.fetch("temps", []).each do |t|
          next unless %w[cpu_thermal nvme].include?(s["name"]) && t["value"] && t["sensor"] == "temp1"

          rep.line(t["value"] >= 75 ? "WARN" : "OK", format("Temperature %s: %.0f °C", s["name"], t["value"]))
        end
      end
    rescue K::ApiError, NoMethodError
      nil
    end
    ph.request("GET", "info/messages").fetch("messages", []).each do |m|
      rep.line("WARN", "Pi-hole message [#{m['type']}]: #{m['plain']}")
    end
    db = ph.request("GET", "info/database")
    rep.line("INFO", format("Query database: %.0f MB, %d rows on disk", db["size"].to_f / 1e6, db["queries_disk"].to_i))

    # Clients that dominate the log, especially the Pi-hole host itself (containers, apps polling a hostname).
    own_ips = ["127.0.0.1", "::1"]
    begin
      ph.request("GET", "network/interfaces")["interfaces"].each do |iface|
        iface.fetch("addresses", []).each { |a| own_ips << a["address"] if a["address"] }
      end
    rescue K::ApiError, NoMethodError
      nil
    end
    ph.request("GET", "stats/top_clients?count=10").fetch("clients", []).each do |c|
      share = total.positive? ? 100.0 * c["count"] / total : 0
      next if share < 25

      who = own_ips.include?(c["ip"]) ? "the Pi-hole host itself" : c["ip"]
      qs = ph.request("GET", "queries?client_ip=#{URI.encode_www_form_component(c['ip'])}&length=2000").fetch("queries", [])
      doms = qs.map { |x| x["domain"] }.tally.max_by(3) { |_, n| n }
      rep.line("WARN", format("%s (%s) sends %.0f%% of all queries; top domains of its last %d: %s. " \
                              "Usually an app polling one hostname: fix the app.",
                              who, c["ip"], share, qs.size, doms.map { |d, n| "#{d} (#{n})" }.join(", ")))
    end

    rep.section("Blocklists")
    lists = ph.request("GET", "lists").fetch("lists", [])
    block = lists.select { |x| x["type"] == "block" }
    enabled = block.select { |x| x["enabled"] }
    rep.line("INFO", "#{enabled.size}/#{block.size} block lists enabled, #{ftl['database']['gravity']} domains on gravity")
    enabled.each do |x|
      rep.line("WARN", "List #{x['id']} #{K::LIST_STATUS[x['status']]}: #{x['address']}") if [3, 4].include?(x["status"])
    end
    hz = {}
    enabled.each { |x| (m = K::HAGEZI_RE.match(x["address"])) && hz[m[1]] = x }
    mains = K::HAGEZI_MAIN.select { |n| hz.key?(n) }
    if mains.size > 1
      rep.line("WARN", "Several HaGeZi Multi tiers enabled (#{mains.join(', ')}): each tier contains the smaller ones. Keep one.")
    end
    tifs = %w[tif tif.medium tif.mini].select { |n| hz.key?(n) }
    rep.line("WARN", "Several TIF sizes enabled (#{tifs.join(', ')}): keep the largest your hardware handles") if tifs.size > 1
    top_tier = mains.last
    if hz.key?("fake") && (!(mains - ["light"]).empty? || !tifs.empty?)
      rep.line("WARN", "HaGeZi Fake (list #{hz['fake']['id']}) is already part of Normal/Pro/Pro++/Ultimate and TIF")
    end
    if hz.key?("popupads") && %w[pro pro.plus ultimate].include?(top_tier)
      rep.line("WARN", "HaGeZi Pop-Up Ads (list #{hz['popupads']['id']}) is already part of #{top_tier}")
    end
    natives = hz.keys.select { |n| n.start_with?("native.") }
    if !natives.empty? && %w[pro.plus ultimate].include?(top_tier)
      rep.line("REVIEW", "Native tracker lists (#{natives.join(', ')}) are mostly/fully covered by #{top_tier}; " \
                         "run `lists overlap` to measure")
    end
    rep.line("REVIEW", "Many lists: run `pihole_tool.rb lists overlap` to see which add live, unique domains") if enabled.size > 6
  end

  def audit_client(ph, rep, test_domain)
    rep.section("This client's DNS path")
    pihole_ips = begin
      Addrinfo.getaddrinfo(ph.host, 53, nil, :DGRAM).map(&:ip_address)
    rescue SocketError
      [ph.host]
    end
    r = K.dns_query(ph.host, test_domain)
    if r.key?("error")
      rep.line("WARN", "Pi-hole did not answer DNS on #{ph.host}:53 (#{r['error']})")
      return
    end
    unless K.blocked_answer?(r)
      rep.line("REVIEW", "Pi-hole does not block test domain #{test_domain} (#{r['rcode']} #{r['answers']}); " \
                         "pick a blocked one with --test-domain")
      return
    end
    rep.line("OK", "Pi-hole blocks #{test_domain} (#{r['rcode']} #{r['answers']})")
    servers, source = client_dns_servers
    if servers.empty?
      rep.line("INFO", "Could not read this machine's DNS servers (Windows: `ipconfig /all`)")
      return
    end
    rep.line("INFO", "DNS servers in use (#{source}): #{servers.join(', ')}")
    servers.each do |s|
      next if pihole_ips.include?(s.split("%").first)

      res = K.dns_query(s, test_domain)
      if res.key?("error")
        rep.line("INFO", "#{s} did not answer (#{res['error']})")
      elsif K.blocked_answer?(res)
        rep.line("OK", "#{s} is not the Pi-hole but also blocks #{test_domain} (it forwards to a filter)")
      else
        rep.line("CRIT", "DNS LEAK: #{s} resolves #{test_domain} → #{res['answers'].empty? ? res['rcode'] : res['answers'].join(', ')}. " \
                         "Clients may use it instead of Pi-hole (ads leak, queries invisible). Hand out only " \
                         "Pi-hole address(es) via DHCP, for IPv4 and IPv6.")
      end
    end
  end

  def audit_host(ph, rep)
    rep.section("Exposure of #{ph.host} (TCP ports seen from this machine)")
    open_ports = probe_ports(ph.host, COMMON_PORTS)
    open_ports.each { |p| rep.line([53, 80, 443].include?(p) ? "OK" : "REVIEW", "#{p}/tcp open: #{COMMON_PORTS[p]}") }
    if open_ports.include?(22)
      methods = ssh_auth_methods(ph.host)
      if methods.intersect?(%w[password keyboard-interactive])
        rep.line("WARN", "SSH accepts password logins (#{methods.join(',')}): switch to keys only")
      elsif !methods.empty?
        rep.line("OK", "SSH auth methods: #{methods.join(',')}")
      end
    end
    audit_vnc(ph.host, rep) if open_ports.include?(5900)
    rep.line("INFO", "Also verify on the router: no port forwards to this host for 53/80/443, and UPnP is off or restricted")
  end

  # RFB security types (IANA registry): 1 None, 2 classic VNC password (DES, 8 characters), 5/6 RA2
  # (RSA-AES), 19 VeNCrypt (TLS), 129 RSA-AES-256 as used by wayvnc on Raspberry Pi OS.
  VNC_TYPES = { 1 => "none", 2 => "VNC password", 5 => "RSA-AES", 6 => "RSA-AES (unencrypted)",
                16 => "Tight", 19 => "VeNCrypt", 129 => "RSA-AES-256" }.freeze

  def audit_vnc(host, rep)
    s = Socket.tcp(host, 5900, connect_timeout: 3)
    version = s.read(12)
    s.write("RFB 003.008\n")
    types = s.read(s.read(1).unpack1("C")).unpack("C*")
    names = types.map { |t| VNC_TYPES.fetch(t, t.to_s) }.join(", ")
    if types.include?(1)
      rep.line("CRIT", "VNC (#{version.strip}) accepts connections WITHOUT authentication (#{names})")
    elsif types.include?(2)
      rep.line("WARN", "VNC offers the classic VNC password (unencrypted session, 8-character DES password) (#{names}): " \
                       "disable it in the VNC server, keep only encrypted login methods")
    else
      rep.line("OK", "VNC requires login over an encrypted method (#{names}); limit 5900 to the PCs that use it")
    end
  rescue SystemCallError, IOError, SocketError, NoMethodError, TypeError
    nil
  ensure
    s&.close
  end

  # ------------------------------------------------------------------------- apply

  def cmd_apply(opts)
    local = K.load_local(opts[:local])
    profile = K.load_profile(opts[:profile], local)
    ph, has_pw = K.connect(opts)
    begin
      unless has_pw
        K.die("Set an admin password first (`pihole_tool.rb set-password`): applying settings to an " \
              "unauthenticated Pi-hole leaves it open to anyone on the network.")
      end
      current = K.flatten(ph.request("GET", "config")["config"])
      only = opts[:only]&.split(",")
      changes = {}
      puts "Profile: #{opts[:profile]}#{local.empty? ? '' : " + #{opts[:local]}"}"
      profile.each do |key, entry|
        next if only && !only.include?(key)

        want = entry["value"]
        if !current.key?(key)
          puts "  skip    #{key}: not supported by this Pi-hole version"
        elsif want.nil?
          puts "  skip    #{key}: network-specific, set it in #{opts[:local]}"
        elsif entry.fetch("apply", true) == false
          puts "  manual  #{key}: #{K.fmt(current[key])} (profile suggests #{K.fmt(want)}; advisory only)" if current[key] != want
        elsif current[key] != want
          changes[key] = want
          puts "  change  #{key}: #{K.fmt(current[key])} → #{K.fmt(want)}"
        end
      end
      if changes.empty?
        puts "Nothing to change."
        return 0
      end
      if changes.key?("webserver.acl")
        me = ph.request("GET", "info/client")["remote_addr"].to_s
        if !me.empty? && !K.acl_allows?(changes["webserver.acl"], me)
          K.die("webserver.acl '#{changes['webserver.acl']}' would lock out this machine (#{me}). Fix the ACL first.")
        end
      end
      unless opts[:yes]
        puts "\nDry run. Re-run with --yes to back up and apply."
        return 0
      end
      puts "Backup written to #{teleporter_backup(ph)}" unless opts[:no_backup]
      ph.request("PATCH", "config", body: { "config" => K.nest(changes) })
      puts "Applied; waiting for FTL to settle..."
      verify(ph, changes) ? 0 : 1
    ensure
      ph.logout
    end
  end

  def verify(ph, expected, timeout: 45)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    mismatched = expected
    while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
      sleep 3
      begin
        current = K.flatten(ph.request("GET", "config")["config"])
      rescue K::ApiError => e
        if e.status == 401
          puts "  session ended by FTL restart; re-run `audit` to confirm the values"
          return true
        end
        if e.message.include?("certificate")
          puts "  #{e.message}\n  The web server moved to HTTPS; re-run `audit --insecure` to confirm the values."
          return true
        end
        next # FTL restarting
      end
      mismatched = expected.reject { |k, v| current[k] == v }
      if mismatched.empty?
        puts "Verified #{expected.size} setting(s)."
        return true
      end
    end
    mismatched.each { |k, v| puts "  NOT applied: #{k} (wanted #{K.fmt(v)})" }
    puts "  If the API stopped answering, FTL may be stuck restarting: `sudo systemctl restart pihole-FTL` " \
         "(Docker: `docker restart <container>`), then re-run `audit`."
    false
  end

  def teleporter_backup(ph)
    data, resp = ph.request("GET", "teleporter", raw: true, timeout: 120)
    name = resp["content-disposition"].to_s[/filename="?([^";]+)/, 1] ||
           "pihole-teleporter-#{Time.now.strftime('%Y%m%d-%H%M%S')}.zip"
    Dir.mkdir(K::BACKUP_DIR) unless Dir.exist?(K::BACKUP_DIR)
    path = File.join(K::BACKUP_DIR, name)
    File.binwrite(path, data)
    File.chmod(0o600, path) # contains password hashes
    path
  end

  def cmd_backup(opts)
    ph, = K.connect(opts)
    puts teleporter_backup(ph)
    0
  ensure
    ph&.logout
  end

  def cmd_set_password(opts)
    ph, has_pw = K.connect(opts)
    begin
      K.die("set-password needs an interactive terminal") unless $stdin.tty?
      new = K.getpass("New admin password: ").to_s
      K.die("use at least 12 characters (a passphrase is fine)") if new.size < 12
      K.die("passwords do not match") if K.getpass("Repeat: ") != new
      ph.request("PATCH", "config", body: { "config" => { "webserver" => { "api" => { "password" => new } } } })
      ph.sid = nil # a password change invalidates all sessions
      check = K::Client.new(ph.base, insecure: opts[:insecure])
      check.login(new)
      check.logout
      puts "Password #{has_pw ? 'changed' : 'set'} and verified. Next: enable 2FA and create an app password " \
           "under Settings → Web interface / API."
      0
    ensure
      ph.logout
    end
  end

  # ------------------------------------------------------------------------- lists

  def find_lists(lists, selectors)
    selectors.map do |sel|
      hits = lists.select { |x| x["id"].to_s == sel }
      hits = lists.select { |x| x["address"].include?(sel) } if hits.empty?
      K.die("selector '#{sel}' matches #{hits.size} lists; use the id from `lists show`") unless hits.size == 1
      hits.first
    end
  end

  def cmd_lists(opts, action, selectors)
    ph, = K.connect(opts)
    begin
      lists = ph.request("GET", "lists").fetch("lists", [])
      case action
      when "show"
        lists.each do |x|
          puts format("%4d %s %-5s %9d  %-28s %s", x["id"], x["enabled"] ? "on " : "off", x["type"], x["number"].to_i,
                      K::LIST_STATUS.fetch(x["status"], "never downloaded"), x["address"])
        end
        return 0
      when "overlap"
        return lists_overlap(lists, opts)
      when "usage"
        return lists_usage(ph, lists, opts)
      end
      targets = find_lists(lists, selectors)
      enable = action == "enable"
      targets.each { |x| puts "  #{enable ? 'enable' : 'disable'} #{x['id']}: #{x['address']}" }
      unless opts[:yes]
        puts "Dry run. Re-run with --yes, then run `gravity`."
        return 0
      end
      targets.each do |x|
        enc = URI.encode_www_form_component(x["address"]).gsub("+", "%20")
        # PUT replaces comment and groups too, so send the current ones back. ?type= is required.
        ph.request("PUT", "lists/#{enc}?type=#{x['type']}",
                   body: { "enabled" => enable, "comment" => x["comment"], "groups" => x.fetch("groups", [0]) })
      end
      puts "Done. Run `pihole_tool.rb gravity` (or `pihole -g`) to rebuild the blocklist."
      0
    ensure
      ph.logout
    end
  end

  def lists_overlap(lists, opts)
    enabled = lists.select { |x| x["enabled"] && x["type"] == "block" }
    base = if opts[:base]
             find_lists(enabled, opts[:base])
           else
             enabled.select { |x| (m = K::HAGEZI_RE.match(x["address"])) && (K::HAGEZI_MAIN + ["tif"]).include?(m[1]) }
           end
    K.die("no HaGeZi Multi/TIF list found; pass --base <id or url-substring> for your main list(s)") if base.empty?
    puts "Base (what the others are compared against):"
    base.each { |x| puts "  #{x['id']}: #{x['address']}" }
    puts "Downloading #{enabled.size} lists..."
    parsed = K.parallel_map(enabled, 8) { |x| K.parse_list(K.fetch_text(x["address"])) }
    parsed = enabled.map { |x| x["id"] }.zip(parsed).to_h
    b_exact = {}
    b_wild = {}
    base.each do |x|
      b_exact.merge!(parsed[x["id"]][0])
      b_wild.merge!(parsed[x["id"]][1])
    end
    rng = Random.new(42)
    resolver = K.resolve_server(opts[:resolver])
    puts "\nLiveness sample: #{opts[:sample]} unique domains per list resolved via #{opts[:resolver]} " \
         "(dead = NXDOMAIN/SERVFAIL/timeout)\n\n"
    puts format("%4s %9s %8s %8s %6s  %s", "id", "entries", "unique", "unique%", "dead%", "list")
    base_ids = base.map { |x| x["id"] }
    enabled.each do |x|
      next if base_ids.include?(x["id"])

      exact, wild = parsed[x["id"]]
      doms = (exact.keys + wild.keys).uniq
      unique = doms.reject { |d| K.covered?(d, b_exact, b_wild) }
      dead_pct = "-"
      if !unique.empty? && opts[:sample].positive?
        sample = unique.sample([opts[:sample], unique.size].min, random: rng)
        dead = K.parallel_map(sample, 24) do |d|
          _, r = K.timed_query(resolver, d, timeout: 2.0)
          r.key?("error") || %w[NXDOMAIN SERVFAIL].include?(r["rcode"])
        end
        dead_pct = format("%.0f", 100.0 * dead.count(true) / sample.size)
      end
      pct = doms.empty? ? 0 : 100.0 * unique.size / doms.size
      puts format("%4d %9d %8d %7.1f%% %6s  %s", x["id"], doms.size, unique.size, pct, dead_pct, x["address"])
    end
    puts "\nunique% ≈ 0 → redundant. High unique% but high dead% → mostly stale entries. " \
         "Disable (don't delete) candidates with `lists disable <id> --yes`, then `gravity`."
    0
  end

  # Which lists actually block what this network queries: every domain blocked in the last N days
  # (from Pi-hole's query database) is checked against every enabled list. "Only this list" = queries
  # that would no longer be blocked if that list were disabled. Pi-hole's own per-query list_id is not
  # used: it names one list per domain (or a placeholder), which hides overlap.
  def lists_usage(ph, lists, opts)
    days = opts.fetch(:days, 30)
    now = Time.now.to_i
    r = ph.request("GET", "stats/database/top_domains?blocked=true&from=#{now - (days * 86_400)}&until=#{now}" \
                          "&count=#{opts.fetch(:top, 20_000)}", timeout: 180)
    blocked = r.fetch("domains", [])
    fetched = blocked.sum { |d| d["count"] }
    enabled = lists.select { |x| x["enabled"] && x["type"] == "block" }
    puts "Blocked in the last #{days} days: #{r['blocked_queries']} queries; analysing the #{blocked.size} most " \
         "blocked domains (#{fetched} queries)."
    puts "Downloading #{enabled.size} lists..."
    parsed = enabled.map { |x| x["id"] }.zip(K.parallel_map(enabled, 8) { |x| K.parse_list(K.fetch_text(x["address"])) }).to_h
    stats = enabled.to_h { |x| [x["id"], { "any" => 0, "only" => 0, "only_domains" => [] }] }
    uncovered = 0
    blocked.each do |d|
      ids = enabled.filter_map { |x| x["id"] if K.covered?(d["domain"], *parsed[x["id"]]) }
      uncovered += d["count"] if ids.empty?
      ids.each { |id| stats[id]["any"] += d["count"] }
      next unless ids.size == 1

      stats[ids.first]["only"] += d["count"]
      stats[ids.first]["only_domains"] << [d["domain"], d["count"]]
    end
    puts format("\n%4s %9s %10s %8s %10s %8s  %s", "id", "entries", "matched", "matched%", "only-this", "domains", "list")
    enabled.sort_by { |x| -stats[x["id"]]["only"] }.each do |x|
      s = stats[x["id"]]
      entries = parsed[x["id"]].sum(&:size)
      share = fetched.positive? ? 100.0 * s["any"] / fetched : 0
      puts format("%4d %9d %10d %7.1f%% %10d %8d  %s", x["id"], entries, s["any"], share, s["only"],
                  s["only_domains"].size, x["address"])
      top = s["only_domains"].max_by(opts.fetch(:examples, 3)) { |_, n| n }
      puts "#{' ' * 16}only here: #{top.map { |dom, n| "#{dom} (#{n})" }.join(', ')}" unless top.empty?
    end
    puts "\n#{uncovered} queries were blocked by regex/denylist entries, CNAME inspection or lists removed since." if uncovered.positive?
    puts "\nmatched = blocked queries whose domain is on the list. only-this = queries that would no longer be " \
         "blocked if this list were disabled. A list with 0 only-this queries adds nothing for this network today; " \
         "check the 'only here' domains before disabling the others."
    0
  end

  def cmd_gravity(opts)
    ph, = K.connect(opts)
    data, = ph.request("POST", "action/gravity", raw: true, timeout: 900)
    puts data.to_s.tr("\r", "\n")
    0
  ensure
    ph&.logout
  end

  # ------------------------------------------------------------------------- CLI

  USAGE = <<~TXT
    Usage: pihole_tool.rb [global options] <command> [options]

    Commands:
      audit                      read-only health and security report (exit 2 = critical, 1 = warnings)
      apply                      apply the profile (dry run unless --yes)
      backup                     download a Teleporter backup to ./backups
      set-password               set or change the admin password
      gravity                    rebuild the blocklist database (pihole -g)
      lists show|overlap|usage|disable|enable [ids or URL substrings]

  TXT

  def main(argv)
    local = K.load_local(K::DEFAULT_LOCAL)
    opts = { url: ENV["PIHOLE_URL"] || local["url"] || "http://pi.hole", insecure: false,
             profile: K::DEFAULT_PROFILE, local: K::DEFAULT_LOCAL, test_domain: "doubleclick.net",
             sample: 100, resolver: "1.1.1.1" }
    # Global options are accepted before and after the command (`audit --insecure` and `--insecure audit`).
    add_global = lambda do |o|
      o.on("--url URL", "Pi-hole base URL (default: $PIHOLE_URL, settings.local.json 'url', http://pi.hole)") { |v| opts[:url] = v }
      o.on("--insecure", "accept Pi-hole's self-signed HTTPS certificate") { opts[:insecure] = true }
      o.on("--profile FILE", "recommended settings profile (JSON)") { |v| opts[:profile] = v }
      o.on("--local FILE", "local overrides (JSON, git-ignored)") { |v| opts[:local] = v }
    end
    global = OptionParser.new do |o|
      o.banner = USAGE + "Global options (before or after the command):"
      add_global.call(o)
    end
    global.order!(argv)
    cmd = argv.shift
    sub = OptionParser.new do |o|
      o.banner = "Usage: pihole_tool.rb #{cmd} [options]"
      add_global.call(o)
      case cmd
      when "audit"
        o.on("--test-domain DOMAIN", "a domain your Pi-hole blocks (leak test)") { |v| opts[:test_domain] = v }
        o.on("--no-client-checks", "skip DNS-path checks of this machine") { opts[:no_client_checks] = true }
        o.on("--no-port-scan", "skip TCP port and SSH checks") { opts[:no_port_scan] = true }
      when "apply"
        o.on("--yes", "really apply (takes a Teleporter backup first)") { opts[:yes] = true }
        o.on("--only KEYS", "comma-separated keys, e.g. dns.blockTTL,dns.upstreams") { |v| opts[:only] = v }
        o.on("--no-backup") { opts[:no_backup] = true }
      when "lists"
        o.on("--base SELECTORS", "overlap: comma-separated ids/URL substrings of your main lists " \
                                 "(default: HaGeZi Multi + TIF)") { |v| opts[:base] = v.split(",") }
        o.on("--sample N", Integer, "overlap: domains per list to liveness-check (0 = skip)") { |v| opts[:sample] = v }
        o.on("--resolver IP", "overlap: NON-filtering public resolver for liveness checks (not the Pi-hole, not " \
                              "Quad9: filtering resolvers answer NXDOMAIN for malware and skew dead%)") { |v| opts[:resolver] = v }
        o.on("--yes", "enable/disable: really change") { opts[:yes] = true }
        o.on("--days N", Integer, "usage: how many days of the query database to analyse (default 30)") { |v| opts[:days] = v }
        o.on("--top N", Integer, "usage: most-blocked domains to fetch (default 20000)") { |v| opts[:top] = v }
        o.on("--examples N", Integer, "usage: 'only here' domains to show per list (default 3)") { |v| opts[:examples] = v }
      end
    end
    sub.parse!(argv)
    case cmd
    when "audit" then cmd_audit(opts)
    when "apply" then cmd_apply(opts)
    when "backup" then cmd_backup(opts)
    when "set-password" then cmd_set_password(opts)
    when "gravity" then cmd_gravity(opts)
    when "lists"
      action = argv.shift
      K.die("lists needs one of: show, overlap, usage, disable, enable") unless %w[show overlap usage disable enable].include?(action)
      K.die("lists #{action} needs at least one list id or URL substring") if %w[enable disable].include?(action) && argv.empty?
      cmd_lists(opts, action, argv)
    else
      puts global.help
      cmd.nil? || %w[-h --help help].include?(cmd) ? 0 : 1
    end
  rescue OptionParser::ParseError => e
    K.die(e.message)
  end
end

if $PROGRAM_NAME == __FILE__
  $stdout.sync = true # keep report lines and error messages in order when piped
  begin
    exit PiholeTool.main(ARGV)
  rescue PiholeKit::ApiError => e
    PiholeKit.die(e.message)
  rescue Interrupt
    exit 130
  end
end
