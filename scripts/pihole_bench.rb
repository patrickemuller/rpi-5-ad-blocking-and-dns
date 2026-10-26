#!/usr/bin/env ruby
# frozen_string_literal: true

# One-minute DNS performance benchmark for Pi-hole, with before/after comparison.
#
# Measures what Pi-hole settings and hardware actually influence, then explains which setting to
# change. Every run is saved to benchmarks/ (git-ignored) and compared with the previous run against
# the same Pi-hole, so you can benchmark, change one setting, and benchmark again.
#
#   ruby scripts/pihole_bench.rb --label baseline
#   ruby scripts/pihole_bench.rb --label "blockTTL=2"      # compares with the previous run
#   ruby scripts/pihole_bench.rb compare [OLD.json NEW.json]
#   ruby scripts/pihole_bench.rb compare --before baseline --after "blockTTL=2"
#   ruby scripts/pihole_bench.rb history
#
# Ruby >= 3.1, standard library only. Uses --url / $PIHOLE_URL / settings.local.json like
# pihole_tool.rb. $PIHOLE_PASSWORD (an app password works) adds server-side metrics; without it the
# benchmark runs client-side only.

require "fileutils"
require "optparse"
require "securerandom"
require_relative "lib/pihole_kit"

module PiholeBench
  K = PiholeKit

  RESULTS_DIR = File.join(K::ROOT, "benchmarks")
  LEDGER = File.join(RESULTS_DIR, ".recent-queries.json") # every run, including --no-save and --json ones
  PREFIX = "pihole-bench-" # every synthetic name starts with this; exclude it in the query log if you like

  CACHED_NAMES = %w[google.com youtube.com apple.com microsoft.com amazon.com wikipedia.org github.com
                    cloudflare.com netflix.com whatsapp.net].freeze
  BLOCK_CANDIDATES = %w[doubleclick.net googlesyndication.com googleadservices.com adnxs.com app-measurement.com
                        scorecardresearch.com taboola.com outbrain.com adservice.google.com criteo.com].freeze
  # Unsigned zones: random names under them can't be answered from NSEC aggressive caching
  # (RFC 8198), so every query is a real cache miss at the upstream's authoritative servers.
  COLD_ZONES = %w[google.com amazon.com microsoft.com apple.com].freeze
  REFERENCE_UPSTREAMS = { "Cloudflare" => "1.1.1.1", "Quad9" => "9.9.9.9", "Google" => "8.8.8.8" }.freeze
  PROVIDER_PAIRS = { "Cloudflare" => ["1.1.1.1", "1.0.0.1"], "Quad9" => ["9.9.9.9", "149.112.112.112"],
                     "Google" => ["8.8.8.8", "8.8.4.4"] }.freeze

  # metric => [label, unit, higher_is_better, relative noise floor, absolute noise floor].
  # A change counts only when it exceeds BOTH floors. They come from repeated runs without any setting
  # change (client on Wi-Fi): cached p50 moved up to ~20% back-to-back; cache misses, which depend on
  # the internet path, moved ~25% back-to-back and 15–35 ms over one day.
  METRICS = {
    "rtt_ms" => ["Network RTT client→Pi (TCP handshake)", "ms", false, 0.25, 1],
    "cached_p50" => ["Cached answer p50", "ms", false, 0.20, 1],
    "cached_p95" => ["Cached answer p95", "ms", false, 0.30, 2],
    "pihole_cache_overhead_ms" => ["Pi-hole time per cached answer (p50 − RTT)", "ms", false, 0.30, 1],
    "blocked_p50" => ["Blocked, repeated domain p50", "ms", false, 0.20, 1],
    "blocked_unique_p50" => ["Blocked, new subdomain p50 (gravity lookup)", "ms", false, 0.20, 1],
    "cold_p50" => ["Cache miss via Pi-hole p50", "ms", false, 0.50, 10],
    "cold_p95" => ["Cache miss via Pi-hole p95", "ms", false, 0.50, 15],
    "best_upstream_p50" => ["Fastest upstream, popular names, p50", "ms", false, 0.25, 3],
    "forward_overhead_ms" => ["Forwarding overhead (miss via Pi-hole − direct)", "ms", false, 0.50, 10],
    "burst_qps" => ["Burst throughput", "q/s", true, 0.25, 200],
    "burst_p95" => ["Burst p95", "ms", false, 0.35, 3],
    "burst_failures" => ["Burst timeouts/refusals", "", false, 0, 1],
    "server_cache_hit_pct" => ["Server: answered from cache (24 h)", "%", true, 0, 2],
    "server_cache_evictions" => ["Server: live cache evictions (total)", "", false, 0, 1],
    "server_load1" => ["Server: load average (1 min)", "", false, 0, 0.5],
    "server_ftl_cpu" => ["Server: FTL CPU after burst", "%", false, 0, 5],
    "server_temp_c" => ["Server: CPU temperature", "°C", false, 0, 3]
  }.freeze
  # Settings captured with each run so `compare` can show what changed between runs.
  SETTINGS = %w[dns.upstreams dns.cache.size dns.cache.optimizer dns.dnssec dns.blockTTL dns.replyWhenBusy
                dns.CNAMEdeepInspect dns.rateLimit.count dns.rateLimit.interval dns.listeningMode misc.nice
                database.DBinterval database.maxDBdays].freeze

  module_function

  def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  # ------------------------------------------------------------------------- measurement

  class Budget
    def initialize(seconds)
      @start = PiholeBench.now
      @end = @start + seconds
    end

    def left = @end - PiholeBench.now
    def elapsed = PiholeBench.now - @start
  end

  def rand_label
    PREFIX + SecureRandom.alphanumeric(10).downcase
  end

  @sent = Hash.new(0)
  @sent_lock = Mutex.new

  # Counts queries per target for the rate-limit bookkeeping.
  def query(addrinfo, name)
    @sent_lock.synchronize { @sent[addrinfo.inspect_sockaddr] += 1 }
    K.timed_query(addrinfo, name)
  end

  def sent_to(addrinfo) = @sent[addrinfo.inspect_sockaddr]

  # Latency percentiles over real answers only. REFUSED (rate limit) and SERVFAIL replies come back
  # fast and would make a broken run look quick, so they count as failures, not samples.
  def summarize(samples)
    times = samples.filter_map { |t, r| t if t && %w[NOERROR NXDOMAIN].include?(r["rcode"]) }
    rcodes = samples.map { |_, r| r["rcode"] || r["error"] || "?" }.tally
    { "n" => samples.size, "ok" => times.size, "timeouts" => rcodes.fetch("timeout", 0),
      "refused" => rcodes.fetch("REFUSED", 0), "servfail" => rcodes.fetch("SERVFAIL", 0),
      "p50" => K.pct(times, 0.5), "p95" => K.pct(times, 0.95), "max" => times.max, "rcodes" => rcodes }
  end

  def sequential(target, names, budget, reserve)
    names.each_with_object([]) do |n, out|
      break out if budget.left < reserve

      out << query(target, n)
    end
  end

  def tcp_rtt(host, budget)
    times = []
    [53, 80, 443].each do |port|
      10.times do
        break if budget.left < 50

        start = now
        begin
          Socket.tcp(host, port, connect_timeout: 1, &:close)
          times << (now - start) * 1000
        rescue SystemCallError, SocketError, IOError
          break
        end
      end
      break unless times.empty?
    end
    K.pct(times, 0.5)
  end

  # ------------------------------------------------------------------------- server snapshot

  def api_client(opts)
    ph = K::Client.new(opts[:url], insecure: opts[:insecure])
    if ph.password_set?
      password = ENV["PIHOLE_PASSWORD"]
      password = K.getpass("Pi-hole password for server metrics (empty = client-side only): ") if password.to_s.empty?
      return nil if password.to_s.empty?

      ph.login(password, ENV["PIHOLE_TOTP"])
    end
    ph
  rescue K::ApiError => e
    warn "  note: server metrics unavailable (#{e.message})"
    nil
  end

  def server_snapshot(ph)
    cfg = K.flatten(ph.request("GET", "config")["config"])
    ftl = ph.request("GET", "info/ftl")["ftl"]
    summary = ph.request("GET", "stats/summary")["queries"]
    system = ph.request("GET", "info/system")["system"]
    temp = begin
      ph.request("GET", "info/sensors")["sensors"]["list"].find { |s| s["name"] == "cpu_thermal" }&.dig("temps", 0, "value")
    rescue K::ApiError, NoMethodError
      nil
    end
    upstreams = {}
    begin
      ph.request("GET", "stats/upstreams")["upstreams"].each do |u|
        next unless u.fetch("port", -1).positive? && u["statistics"]["response"].positive? # 0 = not measured yet

        upstreams["#{u['ip']}##{u['port']}"] = { "count" => u["count"], "mean_ms" => (u["statistics"]["response"] * 1000).round(1) }
      end
    rescue K::ApiError, NoMethodError
      nil
    end
    # The benchmark's own client is excluded: its queries would otherwise top the list.
    me = ph.request("GET", "info/client")["remote_addr"]
    top = ph.request("GET", "stats/top_clients?count=3").fetch("clients", []).reject { |c| c["ip"] == me }
    rate_limited = ph.request("GET", "info/messages").fetch("messages", [])
                     .select { |m| m["type"] == "RATE_LIMIT" && !m["plain"].to_s.include?(" #{me} ") }
                     .map { |m| m["plain"] }
    total = summary["total"].to_i
    db = ftl["database"]
    {
      "version" => ph.request("GET", "info/version")["version"]["ftl"]["local"]["version"],
      "settings" => SETTINGS.to_h { |k| [k, cfg[k]] },
      "queries_24h" => total,
      "cache_hit_pct" => total.positive? ? (100.0 * summary["cached"] / total).round(1) : nil,
      "forwarded_pct" => total.positive? ? (100.0 * summary["forwarded"] / total).round(1) : nil,
      "stale_answered" => ftl.dig("dnsmasq", "dns_stale_answered"),
      "cache_evictions" => ftl.dig("dnsmasq", "dns_cache_live_freed"),
      "gravity_domains" => db["gravity"],
      "lists" => db["lists"],
      "regex_deny" => db.dig("regex", "denied", "enabled"),
      "load" => system["cpu"]["load"]["raw"],
      "nprocs" => system["cpu"]["nprocs"],
      "ftl_cpu" => system.dig("ftl", "%cpu"),
      "temp_c" => temp,
      "upstreams" => upstreams,
      "top_client_share_pct" => top.any? && total.positive? ? (100.0 * top[0]["count"] / total).round(1) : nil,
      "top_client" => top.first&.fetch("ip"),
      "rate_limit_messages" => rate_limited
    }
  end

  # ------------------------------------------------------------------------- run

  def run(opts)
    ph = api_client(opts)
    host = K::Client.new(opts[:url]).host
    target = opts[:server] || host
    pihole = K.resolve_server(target)
    say = opts[:json] ? ->(_) {} : ->(msg) { warn msg }

    server_before = nil
    rate_limit = 1000
    if ph
      say.call("· server snapshot")
      server_before = server_snapshot(ph)
      rate_limit = server_before.dig("settings", "dns.rateLimit.count").to_i
      rate_limit = 100_000 unless rate_limit.positive?
    end
    # One run sends ~310 queries plus the burst to Pi-hole. Keep the total near 42% of the per-client
    # rate limit (default 1000 queries / 60 s) so two runs in the same minute stay under the 90% guard.
    burst_n = [50, [opts[:burst], (rate_limit * 0.42).to_i - 310].min].max
    wait_for_rate_limit(target, 310 + burst_n, rate_limit, say)

    budget = Budget.new(opts[:max_seconds])
    result = { "time" => Time.now.strftime("%Y-%m-%dT%H:%M:%S"), "label" => opts[:label], "target" => target,
               "phases" => {}, "notes" => [] }
    phases = result["phases"]

    say.call("· network RTT")
    result["rtt_ms"] = tcp_rtt(host, budget)

    say.call("· cached answers")
    CACHED_NAMES.each { |n| query(pihole, n) } # warm-up
    phases["cached"] = summarize(sequential(pihole, Array.new(150) { |i| CACHED_NAMES[i % CACHED_NAMES.size] }, budget, 40))

    say.call("· blocked answers")
    blocked = BLOCK_CANDIDATES.select { |n| K.pihole_blocked?(query(pihole, n).last) }
    if blocked.empty?
      result["notes"] << "None of the test ad domains is blocked; blocked-answer tests skipped."
    else
      phases["blocked"] = summarize(sequential(pihole, Array.new(50) { |i| blocked[i % blocked.size] }, budget, 35))
      # New subdomains of a blocked domain force a fresh gravity database lookup every time.
      # Only works when the domain is on an Adblock-style (||domain^) list that covers subdomains.
      uniq = Array.new(40) { |i| "#{rand_label}.#{blocked[i % blocked.size]}" }
      probe = uniq.first(3).map { |n| query(pihole, n) }
      if probe.all? { |_, r| K.pihole_blocked?(r) }
        phases["blocked_unique"] = summarize(probe + sequential(pihole, uniq.drop(3), budget, 30))
      else
        result["notes"] << "No Adblock-style (wildcard) list covers the blocked test domains, so the gravity-lookup test was skipped."
      end
    end

    say.call("· cache misses via Pi-hole")
    cold = Array.new(40) { |i| "#{rand_label}.#{COLD_ZONES[i % COLD_ZONES.size]}" }
    phases["cold"] = summarize(sequential(pihole, cold, budget, 22))

    say.call("· cache misses direct to upstreams")
    candidates = {}
    configured = server_before&.dig("settings", "dns.upstreams") || opts[:upstream] || []
    configured.each { |u| candidates[u] ||= "configured" }
    REFERENCE_UPSTREAMS.each do |prov, ip|
      candidates[ip] = "reference" unless candidates.keys.any? { |u| K.provider_of(u) == prov }
    end
    reachable, local = candidates.keys.partition { |u| !(u.start_with?("127.") || u.start_with?("::1")) }
    local.each { |u| result["notes"] << "Upstream #{u} is local to the Pi and can't be measured from this client." }
    # warm: popular names the upstream almost certainly has cached = what most forwarded queries cost.
    # miss: random names = the upstream's own recursion, to compare with misses via Pi-hole.
    measured = K.parallel_map(reachable, [reachable.size, 1].max) do |u|
      t = K.resolve_server(u)
      CACHED_NAMES.each { |n| K.timed_query(t, n) }
      warm = sequential(t, Array.new(20) { |i| CACHED_NAMES[i % CACHED_NAMES.size] }, budget, 16)
      miss = sequential(t, Array.new(10) { |i| "#{rand_label}.#{COLD_ZONES[i % COLD_ZONES.size]}" }, budget, 14)
      { "warm" => summarize(warm), "miss" => summarize(miss), "role" => candidates[u], "provider" => K.provider_of(u) }
    rescue SocketError
      nil
    end
    phases["direct"] = reachable.zip(measured).to_h.compact

    say.call("· burst (#{burst_n} queries, 25 in parallel)")
    if budget.left > 8
      start = now
      burst = K.parallel_map(Array.new(burst_n) { |i| CACHED_NAMES[i % CACHED_NAMES.size] }, 25) { |n| query(pihole, n) }
      wall = now - start
      phases["burst"] = summarize(burst).merge("qps" => wall.positive? ? (burst.size / wall).round : nil)
    else
      result["notes"] << "Time budget exhausted before the burst test."
    end

    if ph
      begin
        result["server"] = server_snapshot(ph)
        result["server"]["cache_evictions_before"] = server_before["cache_evictions"]
      rescue K::ApiError => e
        result["notes"] << "Server snapshot after the run failed: #{e.message}"
      end
      ph.logout
    else
      result["notes"] << "No password: server-side metrics (cache hit rate, load, settings) not collected."
    end

    result["pihole_queries"] = sent_to(pihole)
    refused = phases.reject { |k, _| k == "direct" }.sum { |_, v| v.fetch("refused", 0) }
    result["rate_limited"] = refused.positive?
    if refused.positive?
      result["notes"] << "#{refused} queries were REFUSED: this client hit Pi-hole's rate limit, so this run " \
                         "is not comparable. Wait a minute and run again."
    end
    result["metrics"] = derive_metrics(result)
    result["duration_s"] = budget.elapsed.round(1)
    record_queries(target, result["pihole_queries"])
    result
  end

  def ledger
    JSON.parse(File.read(LEDGER)).select { |e| Time.now.to_f - e["end"] < 120 }
  rescue SystemCallError, JSON::ParserError, NoMethodError, TypeError
    []
  end

  def record_queries(target, queries)
    FileUtils.mkdir_p(RESULTS_DIR)
    File.write(LEDGER, JSON.generate(ledger + [{ "target" => target, "end" => Time.now.to_f, "queries" => queries }]))
  end

  # Pi-hole refuses a client that sends more than dns.rateLimit.count queries per interval (default
  # 1000/60 s); the client then can't resolve anything until the interval ends. If recent runs plus this
  # one would get close, wait until enough of them are older than a minute.
  def wait_for_rate_limit(target, planned, limit, say)
    t = Time.now.to_f
    recent = ledger.select { |e| e["target"] == target && t - e["end"] < 65 }.map { |e| [e["end"], e["queries"]] }.sort
    until_t = t
    while recent.any? && recent.sum(&:last) + planned > 0.9 * limit
      until_t = recent.shift.first + 65
    end
    return unless until_t > t

    say.call(format("· waiting %.0f s so recent runs don't push this client over Pi-hole's rate limit", until_t - t))
    sleep(until_t - t)
  end

  def derive_metrics(r)
    p = r["phases"]
    m = { "rtt_ms" => r["rtt_ms"] }
    if p["cached"]
      m["cached_p50"] = p["cached"]["p50"]
      m["cached_p95"] = p["cached"]["p95"]
      m["pihole_cache_overhead_ms"] = [0.0, m["cached_p50"] - m["rtt_ms"]].max if m["rtt_ms"] && m["cached_p50"]
    end
    m["blocked_p50"] = p.dig("blocked", "p50") if p["blocked"]
    m["blocked_unique_p50"] = p.dig("blocked_unique", "p50") if p["blocked_unique"]
    if p["cold"]
      m["cold_p50"] = p["cold"]["p50"]
      m["cold_p95"] = p["cold"]["p95"]
    end
    direct = p.fetch("direct", {}).select { |_, d| d.dig("warm", "p50") }
    unless direct.empty?
      best = direct.min_by { |_, d| d["warm"]["p50"] }
      m["best_upstream_p50"] = best[1]["warm"]["p50"]
      m["best_upstream"] = best[0]
      misses = direct.values.select { |d| d["role"] == "configured" }.filter_map { |d| d.dig("miss", "p50") }
      m["forward_overhead_ms"] = m["cold_p50"] - misses.min if misses.any? && m["cold_p50"]
    end
    if (b = p["burst"])
      m["burst_qps"] = b["qps"]
      m["burst_p95"] = b["p95"]
      m["burst_failures"] = b["n"] - b["ok"]
    end
    if (s = r["server"])
      m["server_cache_hit_pct"] = s["cache_hit_pct"]
      m["server_cache_evictions"] = s["cache_evictions"]
      m["server_load1"] = s["load"][0]
      m["server_ftl_cpu"] = s["ftl_cpu"]
      m["server_temp_c"] = s["temp_c"]
    end
    m
  end

  # ------------------------------------------------------------------------- analysis

  # [[severity, finding, what to change]]. Thresholds are for a wired LAN client.
  def tips(r)
    m = r["metrics"]
    s = r["server"] || {}
    st = s.fetch("settings", {})
    out = []
    rtt = m["rtt_ms"]
    c50 = m["cached_p50"]
    c95 = m["cached_p95"]

    if rtt && rtt > 3
      out << ["INFO", format("Network round trip to the Pi is %.1f ms; every answer includes it.", rtt),
              "Not a Pi-hole setting. Wi-Fi typically adds 2–10 ms plus jitter: benchmark from a wired client " \
              "for comparable numbers, and keep the Pi itself on Ethernet."]
    end
    if (ov = m["pihole_cache_overhead_ms"]) && ov > 2
      cause = s["nprocs"] ? format(" Load is %.1f on %d cores.", s["load"][0], s["nprocs"]) : ""
      out << ["WARN", format("Pi-hole needs %.1f ms to answer from cache (healthy: <1 ms).%s", ov, cause),
              "Something on the Pi competes for CPU or I/O. Keep misc.nice at -10 (`sudo pihole-FTL --config " \
              "misc.nice -10`), cap other containers (`--cpus=3`), check `vcgencmd get_throttled` (want 0x0) " \
              "and move off a slow SD card to NVMe/SSD."]
    end
    if c50 && c95 && c95 > 4 * c50 && c95 > 5
      out << ["WARN", format("Cached answers are jittery: p95 %.1f ms vs p50 %.1f ms.", c95, c50),
              "Usually Wi-Fi on the client or the Pi, or bursts of CPU/disk work on the Pi (media transcoding, " \
              "backups, gravity updates). Repeat on a wired client to tell them apart."]
    end
    b = m["blocked_p50"]
    bu = m["blocked_unique_p50"]
    if bu && c50 && bu - c50 > 3
      detail = s.empty? ? "" : " (#{s['gravity_domains']} domains on #{s['lists']} lists, #{s['regex_deny']} deny regexes)"
      out << ["WARN", format("A gravity lookup for a new domain costs %.1f ms extra%s.", bu - c50, detail),
              "Every new domain is checked against the gravity database and every regex. Disable redundant " \
              "lists (`pihole_tool.rb lists overlap`), replace deny regexes with Adblock-style `||domain^` " \
              "entries where possible, and keep the database on NVMe/SSD."]
    elsif b && c50 && b - c50 > 2
      out << ["INFO", format("Repeated blocked answers are %.1f ms slower than cached ones.", b - c50),
              "Usually noise; if it persists, check CPU load during the run."]
    end

    fo = m["forward_overhead_ms"]
    cold = m["cold_p50"]
    if fo && cold && fo > 15 && fo > 0.3 * (cold - fo)
      fix = if st["dns.dnssec"]
              "dns.dnssec is on: Pi-hole fetches and checks DNSKEY/DS records itself on cache misses. With " \
                "validating upstreams (Quad9, Cloudflare, Google) that's duplicate work: " \
                "`sudo pihole-FTL --config dns.dnssec false`."
            elsif (st["dns.upstreams"] || []).any? { |u| u.start_with?("127.") }
              "The upstream is a local recursive resolver: cache misses walk the DNS tree, which is slower by " \
                "design. Enable `prefetch: yes` and `serve-expired: yes` in unbound and keep dns.cache.optimizer at 3600."
            else
              "Check the Pi's own uplink (Wi-Fi?), its load, and whether several upstreams are configured: " \
                "Pi-hole keeps re-testing all of them, including slow ones."
            end
      out << ["WARN", format("Pi-hole adds %.0f ms when forwarding a cache miss (cold %.0f ms).", fo, cold), fix]
    end

    # Upstream choice. Popular-name (warm) latency is what most forwarded queries cost. Pi-hole's own
    # per-upstream mean (real traffic, measured from the Pi) beats the client-side sample when available.
    direct = r["phases"].fetch("direct", {}).select { |_, d| d.dig("warm", "p50") }
    conf = direct.select { |_, d| d["role"] == "configured" }.transform_values { |d| d["warm"]["p50"] }
    if direct.any? && conf.any?
      best_u, best_d = direct.min_by { |_, d| d["warm"]["p50"] }
      best_conf, bc = conf.min_by { |_, v| v }
      bd = best_d["warm"]["p50"]
      if best_d["role"] == "reference" && bc - bd > [5, 0.2 * bc].max
        pair = PROVIDER_PAIRS.fetch(best_d["provider"], [best_u])
        out << ["TIP", format("%s answers in %.0f ms vs %.0f ms for your fastest configured upstream (%s), " \
                              "measured from this client.", best_d["provider"], bd, bc, best_conf),
                "`sudo pihole-FTL --config dns.upstreams '#{JSON.generate(pair)}'` (if you trust its privacy " \
                "policy). Benchmark again afterwards."]
      end
    end
    seen = s.fetch("upstreams", {}).select { |_, v| v["count"] >= 50 }.to_h { |u, v| [u.split("#").first, v["mean_ms"]] }
    ranking, source = seen.size > 1 ? [seen, "Pi-hole's own mean response time"] : [conf, "measured from this client"]
    if ranking.size > 1
      fastest, fv = ranking.min_by { |_, v| v }
      slow = ranking.select { |_, v| v > 1.8 * fv && v - fv > 5 }.keys
      if slow.any?
        detail = ([fastest] + slow).map { |u| format("%s %.0f ms", u, ranking[u]) }.join(", ")
        out << ["TIP", "Upstream(s) #{slow.join(', ')} answer far slower than #{fastest} (#{detail}; #{source}).",
                "Pi-hole keeps sending a share of queries to every configured upstream to re-measure them. " \
                "Keep only the fast provider's pair in dns.upstreams."]
      end
    end
    if cold && cold > 80
      opt = st["dns.cache.optimizer"]
      extra = opt && opt <= 0 ? " (it is currently disabled: `sudo pihole-FTL --config dns.cache.optimizer 3600`)" : ""
      out << ["INFO", format("Cache misses take %.0f ms; about %.0f%% of real queries are misses.", cold, 100 - (s["cache_hit_pct"] || 90)),
              "Keep dns.cache.optimizer at 3600 so expired popular records are served instantly while they refresh#{extra}."]
    end

    if (burst = r["phases"]["burst"])
      if burst["refused"].to_i.positive?
        out << ["WARN", "#{burst['refused']} burst queries were REFUSED: the per-client rate limit " \
                        "(#{st.fetch('dns.rateLimit.count', 1000)}/#{st.fetch('dns.rateLimit.interval', 60)} s) was hit.",
                "Wait a minute before re-running. If a real client hits it (check Pi-hole's messages), fix that " \
                "client, or raise dns.rateLimit.count."]
      end
      if burst["timeouts"].positive?
        busy = st["dns.replyWhenBusy"] == "DROP" ? " dns.replyWhenBusy=DROP also drops queries during list reloads: set ALLOW." : ""
        out << ["WARN", "#{burst['timeouts']} of #{burst['n']} burst queries timed out.",
                "Lost UDP packets mean the Pi (or Wi-Fi) is saturated.#{busy}"]
      end
      if c95 && burst["p95"] && burst["p95"] > 5 * c95 && burst["p95"] > 10
        out << ["INFO", format("Under parallel load p95 rises to %.0f ms (idle %.1f ms).", burst["p95"], c95),
                "Fine for a home network unless it comes with timeouts. Free up CPU on the Pi if it does."]
      end
    end

    return out if s.empty?

    if s["cache_evictions"].to_i.positive?
      size = st.fetch("dns.cache.size", 10_000)
      bigger = [size * 2, 50_000].min
      out << ["TIP", "The cache evicted #{s['cache_evictions']} still-valid records since FTL started.",
              "Raise dns.cache.size moderately (#{size} → #{bigger}): `sudo pihole-FTL --config dns.cache.size " \
              "#{bigger}`. Above ~10k lookups get slower, so don't go big."]
    else
      out << ["OK", "The cache never had to evict a valid record: dns.cache.size is big enough.",
              "Leave it at its current value; a bigger cache only slows lookups."]
    end
    if s["nprocs"] && s["load"][1] > 0.7 * s["nprocs"]
      out << ["WARN", format("5-minute load %.1f on %d cores.", s["load"][1], s["nprocs"]),
              "Other workloads on the Pi are close to saturating it; DNS latency will follow."]
    end
    if s["temp_c"] && s["temp_c"] >= 80
      out << ["WARN", format("CPU at %.0f °C: the Pi 5 throttles from 85 °C.", s["temp_c"]), "Add the Active Cooler or a case fan."]
    end
    s.fetch("rate_limit_messages", []).each do |msg|
      out << ["WARN", "Pi-hole reports: #{msg}",
              "That device gets no DNS answers while rate-limited, which looks like a dead internet connection. " \
              "Find out why it sends so many queries (top domains in the Query Log); raise dns.rateLimit.count " \
              "only if the traffic is legitimate."]
    end
    if s["top_client_share_pct"].to_f > 25
      out << ["INFO", format("One client (%s) sends %.0f%% of all queries.", s["top_client"], s["top_client_share_pct"]),
              "Cheap if they're cache hits, but it bloats the query database. Fix the polling app; " \
              "`pihole_tool.rb audit` shows which domain it is."]
    end
    if st.fetch("database.DBinterval", 60) < 60
      out << ["TIP", "database.DBinterval is #{st['database.DBinterval']} s.",
              "Writing the query log to disk more often than every 60 s only adds I/O."]
    end
    out
  end

  # ------------------------------------------------------------------------- reporting

  def fmt_val(v, unit = "")
    return "-" if v.nil?

    v = v.abs < 100 ? format("%.1f", v) : format("%.0f", v) if v.is_a?(Float)
    "#{v} #{unit}".strip
  end

  def print_report(r)
    puts "\nPi-hole benchmark #{r['time']}  target #{r['target']}  label #{r['label'] || '-'}  (#{r['duration_s']} s)"
    s = r["server"]
    puts "FTL #{s['version']}, #{s['gravity_domains']} domains on #{s['lists']} lists, #{s['queries_24h']} queries/24 h" if s
    puts
    METRICS.each do |key, (label, unit)|
      puts format("  %-50s %10s", label, fmt_val(r["metrics"][key], unit)) unless r["metrics"][key].nil?
    end
    direct = r["phases"].fetch("direct", {})
    unless direct.empty?
      puts "\n  Upstreams (p50 from this client; 'Pi-hole mean' = real traffic measured by the Pi):"
      puts format("    %-18s %-11s %-10s %8s %8s %13s", "server", "provider", "role", "popular", "miss", "Pi-hole mean")
      direct.sort_by { |_, d| d.dig("warm", "p50") || 1e9 }.each do |u, d|
        us = s&.dig("upstreams", "#{u}#53")
        served = us ? "#{us['mean_ms']} ms (#{us['count']})" : "-"
        puts format("    %-18s %-11s %-10s %8s %8s %13s", u, d["provider"], d["role"], fmt_val(d.dig("warm", "p50"), "ms"),
                    fmt_val(d.dig("miss", "p50"), "ms"), served)
      end
    end
    r["notes"].each { |n| puts "\n  note: #{n}" }
    found = tips(r)
    return if found.empty?

    puts "\nFindings and tips:"
    found.each { |sev, finding, change| puts format("  [%-4s] %s\n         → %s", sev, finding, change) }
  end

  def compare(old, new)
    puts "\nCompare  #{old['time']} (#{old['label'] || '-'})  →  #{new['time']} (#{new['label'] || '-'})"
    puts "  warning: different targets (#{old['target']} vs #{new['target']})" if old["target"] != new["target"]
    { "before" => old, "after" => new }.each do |side, run_|
      puts "  warning: the #{side} run was rate-limited by Pi-hole (REFUSED answers); its numbers are not valid" if run_["rate_limited"]
    end
    puts format("\n  %-50s %10s %10s %9s", "metric", "before", "after", "change")
    METRICS.each do |key, (label, unit, higher_better, rel_floor, abs_floor)|
      a = old["metrics"][key]
      b = new["metrics"][key]
      next if a.nil? && b.nil?

      change = ""
      verdict = ""
      if a && b
        diff = b - a
        rel = a.zero? ? (diff.zero? ? 0 : 1) : diff.to_f / a
        noise = diff.abs < abs_floor || rel.abs < rel_floor
        verdict = noise ? "≈" : ((diff.positive? == higher_better) ? "better" : "WORSE")
        change = !a.zero? && rel_floor.positive? ? format("%+.0f%%", rel * 100) : format("%+.1f", diff).sub(/\.0\z/, "")
      end
      puts format("  %-50s %10s %10s %9s %s", label, fmt_val(a, unit), fmt_val(b, unit), change, verdict)
    end
    puts "\n  ≈ = within run-to-run noise. For small effects run each setup 2–3 times with the same label and use" \
         "\n      `compare --before <label> --after <label>` (medians across runs)."
    sa = old.dig("server", "settings") || {}
    sb = new.dig("server", "settings") || {}
    if sa.empty? || sb.empty?
      missing = [("before" if sa.empty?), ("after" if sb.empty?)].compact.join(" and ")
      puts "\n  Settings not recorded for the #{missing} run(s) (no $PIHOLE_PASSWORD), so changes can't be listed."
      return
    end
    changed = (sa.keys | sb.keys).reject { |k| sa[k] == sb[k] }.sort
    if changed.any?
      puts "\n  Settings changed between runs:"
      changed.each { |k| puts "    #{k}: #{JSON.generate(sa[k])} → #{JSON.generate(sb[k])}" }
    else
      puts "\n  No benchmarked settings changed between these runs (differences are noise or load)."
    end
  end

  def saved_runs(target = nil)
    runs = Dir.glob(File.join(RESULTS_DIR, "*.json")).sort
    target ? runs.select { |f| JSON.parse(File.read(f))["target"] == target } : runs
  end

  # Median of every metric across all saved runs with this label.
  def aggregate(label)
    runs = saved_runs.map { |f| JSON.parse(File.read(f)) }.select { |r| r["label"] == label }
    K.die("no saved runs with label '#{label}' (see `history`)") if runs.empty?
    metrics = METRICS.keys.each_with_object({}) do |key, h|
      vals = runs.filter_map { |r| r["metrics"][key] }
      h[key] = K.pct(vals, 0.5) unless vals.empty?
    end
    { "time" => "#{runs.size} run(s)", "label" => label, "target" => runs.last["target"], "metrics" => metrics,
      "server" => runs.last["server"], "rate_limited" => runs.any? { |r| r["rate_limited"] } }
  end

  def save(r)
    FileUtils.mkdir_p(RESULTS_DIR)
    slug = r["label"].to_s.gsub(/[^A-Za-z0-9_-]/, "-")[0, 40]
    path = File.join(RESULTS_DIR, "#{r['time'].delete(':-')}#{slug.empty? ? '' : "-#{slug}"}.json")
    File.write(path, JSON.pretty_generate(r))
    path
  end

  def history
    puts format("%-20s %-26s %7s %8s %6s %6s %5s  (ms, p50)", "time", "label", "cached", "gravity", "cold", "qps", "fail")
    saved_runs.each do |f|
      d = JSON.parse(File.read(f))
      m = d["metrics"]
      puts format("%-20s %-26s %7s %8s %6s %6s %5s%s", d["time"], (d["label"] || "-")[0, 26], fmt_val(m["cached_p50"]),
                  fmt_val(m["blocked_unique_p50"]), fmt_val(m["cold_p50"]), fmt_val(m["burst_qps"]),
                  fmt_val(m["burst_failures"]), d["rate_limited"] ? "  RATE-LIMITED" : "")
    end
  end

  # ------------------------------------------------------------------------- CLI

  USAGE = <<~TXT
    Usage: pihole_bench.rb [run] [options]
           pihole_bench.rb compare [OLD.json NEW.json] [--before LABEL --after LABEL]
           pihole_bench.rb history

  TXT

  def main(argv)
    local = K.load_local(K::DEFAULT_LOCAL)
    opts = { url: ENV["PIHOLE_URL"] || local["url"] || "http://pi.hole", insecure: false,
             max_seconds: 60.0, burst: 200 }
    parser = OptionParser.new do |o|
      o.banner = USAGE + "Options:"
      o.on("--url URL", "Pi-hole base URL (default: $PIHOLE_URL, settings.local.json 'url', http://pi.hole)") { |v| opts[:url] = v }
      o.on("--insecure", "accept Pi-hole's self-signed HTTPS certificate") { opts[:insecure] = true }
      o.on("--label TEXT", "short description of the current setup, e.g. 'after list cleanup'") { |v| opts[:label] = v }
      o.on("--server IP[#PORT]", "DNS server to test (default: the host of --url)") { |v| opts[:server] = v }
      o.on("--upstream IP", "upstream to compare when no password is available (repeatable)") { |v| (opts[:upstream] ||= []) << v }
      o.on("--max-seconds N", Float, "hard time budget (default 60)") { |v| opts[:max_seconds] = v }
      o.on("--burst N", Integer, "queries in the parallel burst test (capped by the rate limit)") { |v| opts[:burst] = v }
      o.on("--no-save", "don't store the result") { opts[:no_save] = true }
      o.on("--json", "print the raw result as JSON") { opts[:json] = true }
      o.on("--before LABEL", "compare: median of all runs with this label") { |v| opts[:before] = v }
      o.on("--after LABEL", "compare: median of all runs with this label") { |v| opts[:after] = v }
    end
    parser.parse!(argv)
    cmd = argv.first if %w[run compare history].include?(argv.first)
    argv.shift if cmd

    case cmd
    when "history"
      history
    when "compare"
      if opts[:before] && opts[:after]
        compare(aggregate(opts[:before]), aggregate(opts[:after]))
      else
        files = argv.empty? ? saved_runs.last(2) : argv
        K.die("need two saved runs (run the benchmark twice, or pass two files)") unless files.size == 2
        compare(*files.map { |f| JSON.parse(File.read(f)) })
      end
    else
      result = run(opts)
      opts[:json] ? puts(JSON.pretty_generate(result)) : print_report(result)
      previous = saved_runs(result["target"])
      puts "\nSaved #{save(result).delete_prefix("#{K::ROOT}/")}" unless opts[:no_save]
      compare(JSON.parse(File.read(previous.last)), result) if previous.any? && !opts[:json]
    end
    0
  rescue OptionParser::ParseError => e
    K.die(e.message)
  end
end

if $PROGRAM_NAME == __FILE__
  $stdout.sync = true # keep report lines and error messages in order when piped
  begin
    exit PiholeBench.main(ARGV)
  rescue PiholeKit::ApiError => e
    PiholeKit.die(e.message)
  rescue Interrupt
    exit 130
  end
end
