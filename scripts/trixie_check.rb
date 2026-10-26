#!/usr/bin/env ruby
# frozen_string_literal: true

# Read-only readiness check for moving a Raspberry Pi from Raspberry Pi OS bookworm (Debian 12) to
# trixie (Debian 13): what runs on the Pi, what has to be backed up and recreated, and what may not
# exist or behave differently on trixie.
#
#   ruby scripts/trixie_check.rb --host <user>@<pi-ip>     # collect over SSH, then analyse
#   ruby scripts/trixie_check.rb --from inventory/<file>   # analyse a saved inventory again
#
# Nothing is changed on the Pi. The collector only reads; commands that need root use `sudo -n` and
# are skipped if sudo would ask for a password. The raw inventory is saved to inventory/ (git-ignored).
# Ruby >= 3.1, standard library only; runs on your computer, nothing to install on the Pi.

require "net/http"
require "open3"
require "optparse"
require "set"
require "stringio"
require "uri"
require "zlib"

module TrixieCheck
  ROOT = File.expand_path("..", __dir__)
  INVENTORY_DIR = File.join(ROOT, "inventory")

  # POSIX sh (dash on the Pi). Each section starts with a "### name" line.
  COLLECTOR = <<~'SH'
    sec() { printf '\n### %s\n' "$1"; }
    sec os;              cat /etc/os-release
    sec kernel;          uname -srvm
    sec arch;            dpkg --print-architecture
    sec model;           tr -d '\000' < /proc/device-tree/model 2>/dev/null; echo
    sec root;            findmnt -no SOURCE,FSTYPE /
    sec disks;           lsblk -dno NAME,SIZE,TRAN 2>/dev/null
    sec boot_free;       df -Pm /boot/firmware 2>/dev/null | tail -n 1
    sec boot_order;      (rpi-eeprom-config 2>/dev/null || sudo -n rpi-eeprom-config 2>/dev/null) | grep -i '^BOOT_ORDER'
    sec default_target;  systemctl get-default
    sec sources
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
      [ -f "$f" ] || continue
      echo "== $f"
      grep -Ev '^[[:space:]]*(#|$)' "$f"
    done
    sec manual;          apt-mark showmanual
    sec services;        systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager
    sec listening;       sudo -n ss -tulpnH 2>/dev/null || ss -tulnH
    sec docker
    if command -v docker >/dev/null 2>&1; then
      D=docker; docker ps >/dev/null 2>&1 || D="sudo -n docker"
      $D ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Label "com.docker.compose.project.config_files"}}' 2>/dev/null
      echo "== mounts"
      for c in $($D ps -aq 2>/dev/null); do
        $D inspect --format '{{.Name}}{{range .Mounts}}|{{.Type}}:{{.Source}}{{end}}' "$c" 2>/dev/null
      done
    fi
    sec crontab;         crontab -l 2>/dev/null; sudo -n crontab -l -u root 2>/dev/null
    sec cron_d;          ls /etc/cron.d 2>/dev/null
    sec sysctl_conf;     grep -Ev '^[[:space:]]*(#|;|$)' /etc/sysctl.conf 2>/dev/null
    sec pam_environment; ls /home/*/.pam_environment /root/.pam_environment 2>/dev/null
    sec dsa_keys;        grep -ls 'ssh-dss' /home/*/.ssh/authorized_keys 2>/dev/null; ls /etc/ssh/ssh_host_dsa_key 2>/dev/null
    sec tmp_mb;          du -sm /tmp 2>/dev/null | cut -f1
    sec pihole;          pihole -v 2>/dev/null
    sec pivpn;           command -v pivpn 2>/dev/null
    sec wireguard;       ls /etc/wireguard 2>/dev/null || sudo -n ls /etc/wireguard 2>/dev/null
    sec samba;           testparm -s 2>/dev/null | grep -E '^\[|^[[:space:]]*path ='
    sec vnc;             systemctl is-enabled wayvnc 2>/dev/null; systemctl is-enabled vncserver-x11-serviced 2>/dev/null
    sec nftables;        ls /etc/nftables.conf 2>/dev/null; systemctl is-enabled nftables 2>/dev/null
    sec fstab;           grep -Ev '^[[:space:]]*(#|$)' /etc/fstab
    sec config_txt;      grep -Ev '^[[:space:]]*(#|$)' /boot/firmware/config.txt 2>/dev/null
    sec home;            ls /home
    sec local_bin;       ls /usr/local/bin /opt 2>/dev/null
  SH

  # Services every Raspberry Pi OS image enables; anything else is yours to recreate.
  STOCK_SERVICES = %w[
    alsa-utils apparmor avahi-daemon bluetooth console-setup cron cups cups-browsed dbus dphys-swapfile e2scrub_reap
    fake-hwclock getty@ glamor-test hciuart keyboard-setup lightdm ModemManager NetworkManager
    NetworkManager-dispatcher NetworkManager-wait-online nfs-client.target raspberrypi-net-mods rp1-test
    rpi-display-backlight rpi-eeprom-update rpi-resize-swap-file rsync rsyslog serial-getty@ ssh sshswitch
    systemd-pstore systemd-timesyncd triggerhappy udisks2 userconfig wpa_supplicant regenerate_ssh_host_keys
    systemd-network-generator rpi-resize systemd-zram-setup@ cloud-init-local cloud-init cloud-config cloud-final
  ].to_set.freeze

  DEBIAN_TRIXIE = %w[main contrib non-free non-free-firmware].map do |c|
    "https://deb.debian.org/debian/dists/trixie/#{c}/binary-arm64/Packages.gz"
  end.freeze
  RPI_TRIXIE = "https://archive.raspberrypi.com/debian/dists/trixie/main/binary-arm64/Packages.gz"

  # BOOT_ORDER is read right to left, one hex digit per boot mode.
  BOOT_MODES = { "1" => "SD card", "2" => "network", "4" => "USB", "5" => "BCM-USB", "6" => "NVMe",
                 "7" => "HTTP", "e" => "stop", "f" => "restart" }.freeze

  class Report
    def initialize
      @counts = Hash.new(0)
    end

    def section(title) = puts("\n== #{title}")

    def line(level, msg)
      @counts[level] += 1
      puts format("  [%-6s] %s", level, msg)
    end

    def summary
      puts "\nSummary: #{%w[BLOCK WARN TODO OK].select { |k| @counts[k].positive? }.map { |k| "#{@counts[k]} #{k}" }.join(', ')}"
    end
  end

  module_function

  # ------------------------------------------------------------------------- collection

  def collect(opts)
    cmd = opts[:via] ? ["sh", "-c", opts[:via]] : ["ssh", "-o", "ConnectTimeout=10", opts[:host], "sh -s"]
    out, err, status = Open3.capture3(*cmd, stdin_data: COLLECTOR)
    abort "collection failed (exit #{status.exitstatus}): #{err.strip}" unless status.success? || out.include?("### os")
    Dir.mkdir(INVENTORY_DIR) unless Dir.exist?(INVENTORY_DIR)
    name = (opts[:host] || "via").gsub(/[^A-Za-z0-9._-]/, "_")
    path = File.join(INVENTORY_DIR, "#{name}-#{Time.now.strftime('%Y%m%d-%H%M%S')}.txt")
    File.write(path, out)
    [out, path]
  end

  def sections(text)
    text.split(/^### /).drop(1).to_h do |chunk|
      name, body = chunk.split("\n", 2)
      [name.strip, body.to_s.lines.map(&:rstrip).reject(&:empty?)]
    end
  end

  # ------------------------------------------------------------------------- package indexes

  def http_get(url, limit = 5)
    uri = URI(url)
    resp = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https", open_timeout: 15, read_timeout: 120) do |h|
      h.request(Net::HTTP::Get.new(uri, "User-Agent" => "trixie-check/1.0"))
    end
    return http_get(URI.join(url, resp["location"]).to_s, limit - 1) if resp.is_a?(Net::HTTPRedirection) && limit.positive?

    resp.is_a?(Net::HTTPSuccess) ? resp.body : nil
  rescue SystemCallError, SocketError, IOError, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError
    nil
  end

  # Package and Provides names from a Packages(.gz) index.
  def index_names(url)
    body = http_get(url)
    return nil unless body

    body = Zlib::GzipReader.new(StringIO.new(body)).read if url.end_with?(".gz")
    names = Set.new
    body.each_line do |line|
      if line.start_with?("Package: ")
        names << line[9..].strip
      elsif line.start_with?("Provides: ")
        line[10..].split(",").each { |p| names << p.strip.split(" ").first }
      end
    end
    names
  end

  # apt sources in one-line and deb822 format -> [{uri:, suite:, components:, file:}]
  def parse_sources(lines)
    out = []
    file = nil
    block = {}
    flush = lambda do
      if block["uris"] && block["suites"]
        block["uris"].split.each do |u|
          block["suites"].split.each do |s|
            out << { uri: u.chomp("/"), suite: s, components: block["components"].to_s.split, file: file }
          end
        end
      end
      block = {}
    end
    lines.each do |l|
      if l.start_with?("== ")
        flush.call
        file = l[3..]
      elsif (m = l.match(/\Adeb\s+(?:\[[^\]]*\]\s+)?(\S+)\s+(\S+)\s*(.*)\z/))
        out << { uri: m[1].chomp("/"), suite: m[2], components: m[3].split, file: file }
      elsif (m = l.match(/\A(Types|URIs|Suites|Components):\s*(.*)\z/i))
        block[m[1].downcase] = m[2]
      end
    end
    flush.call
    out
  end

  # ------------------------------------------------------------------------- analysis

  def analyse(text, rep, opts)
    s = sections(text)
    os = s.fetch("os", []).to_h { |l| l.split("=", 2) }.transform_values { |v| v.to_s.delete('"') }
    arch = s.fetch("arch", []).first.to_s
    codename = os["VERSION_CODENAME"].to_s

    rep.section("System")
    model = s.fetch("model", []).first.to_s
    rep.line("OK", [model, os["PRETTY_NAME"], arch].reject(&:empty?).join(", "))
    kernel = s.fetch("kernel", ["?"]).first
    if model.include?("Raspberry Pi")
      rep.line("OK", "Kernel #{kernel}. It comes from Raspberry Pi's own repository (not Debian's), is updated on " \
                     "bookworm and trixie alike, and is not what goes out of support")
    else
      rep.line("INFO", "Kernel #{kernel}")
    end
    case codename
    when "bookworm"
      rep.line("TODO", "Debian 12 userland: regular security support ended 2026-07-11, LTS (fewer packages) until 2028-06-30")
    when "trixie"
      rep.line("OK", "Already on trixie")
    end
    if arch == "armhf"
      rep.line("WARN", "32-bit (armhf): trixie switches to 64-bit time_t, and Raspberry Pi recommends the 64-bit image on a Pi 5")
    end
    root = s.fetch("root", []).first.to_s
    rep.line("INFO", "Root filesystem: #{root}")
    boot_check(s, root, rep)
    if (free = s.fetch("boot_free", []).first)
      avail = free.split[3].to_i
      rep.line(avail < 300 ? "WARN" : "OK", "/boot/firmware has #{avail} MB free (Debian asks for ~300 MB for upgrades)")
    end
    target = s.fetch("default_target", []).first.to_s
    unless target.empty?
      rep.line("INFO", "Default target #{target}: install the #{target.include?('graphical') ? 'Desktop' : 'Lite'} image of trixie")
    end

    rep.section("APT sources")
    sources = parse_sources(s.fetch("sources", []))
    third = sources.reject { |src| src[:uri].match?(%r{deb\.debian\.org|security\.debian\.org|archive\.raspberrypi\.(com|org)|raspbian\.raspberrypi}) }
    if third.empty?
      rep.line("OK", "Only Debian and Raspberry Pi repositories")
    else
      third.uniq { |src| [src[:uri], src[:suite]] }.each do |src|
        suite = src[:suite].sub("bookworm", "trixie")
        ok = suite != src[:suite] && http_get("#{src[:uri]}/dists/#{suite}/Release")
        if suite == src[:suite]
          rep.line("INFO", "#{src[:uri]} #{src[:suite]} (not release-specific; check the vendor's trixie support) [#{src[:file]}]")
        else
          rep.line(ok ? "OK" : "BLOCK", "#{src[:uri]}: #{ok ? 'has' : 'has NO'} '#{suite}' suite [#{src[:file]}]")
        end
      end
    end

    package_check(s, sources, third, rep) unless opts[:no_packages]

    rep.section("Services and data to carry over")
    services = s.fetch("services", []).map { |l| l.split.first.to_s.delete_suffix(".service") }
    custom = services.reject { |n| STOCK_SERVICES.include?(n) || STOCK_SERVICES.include?(n.sub(/@.*/, "@")) || n.start_with?("systemd-") }
    rep.line("TODO", "Enabled services to recreate: #{custom.join(', ')}") unless custom.empty?
    listening = s.fetch("listening", []).filter_map do |l|
      f = l.split
      local = f[4].to_s
      next if local.start_with?("127.", "[::1]", "::1")

      proc_name = l[/users:\(\("([^"]+)"/, 1]
      "#{f[0]} #{local.split(':').last}#{proc_name ? " (#{proc_name})" : ''}"
    end.uniq
    rep.line("INFO", "Listening on the network: #{listening.join(', ')}") unless listening.empty?

    pihole_check(s, rep)
    vpn_check(s, rep)
    docker_check(s, rep)
    samba = s.fetch("samba", [])
    unless samba.empty?
      shares = samba.select { |l| l.start_with?("[") }.map { |l| l.delete("[]") } - %w[global]
      rep.line("TODO", "Samba shares #{shares.join(', ')}: copy /etc/samba/smb.conf; Samba users must be re-added " \
                       "with `smbpasswd -a <user>` (passwords live in /var/lib/samba/private)")
    end
    vnc = s.fetch("vnc", [])
    if vnc.include?("enabled")
      rep.line("TODO", "VNC is enabled: needs the Desktop image; enable it again with `sudo raspi-config nonint do_vnc 0`")
    end
    if s.fetch("nftables", []).include?("enabled")
      rep.line("TODO", "Custom firewall: copy /etc/nftables.conf and `systemctl enable nftables`")
    end
    cron = s.fetch("crontab", []).reject { |l| l.start_with?("#") }
    rep.line("TODO", "Crontab entries to copy: #{cron.size}") unless cron.empty?
    cron_d = s.fetch("cron_d", []) - %w[e2scrub_all pihole raspi-firmware .placeholder]
    rep.line("TODO", "Custom files in /etc/cron.d: #{cron_d.join(', ')}") unless cron_d.empty?
    fstab = s.fetch("fstab", []).reject { |l| l.match?(%r{\s/(boot(/firmware)?)?\s}) || l.include?("proc") }
    rep.line("TODO", "Extra mounts in /etc/fstab: #{fstab.map { |l| l.split[1] }.join(', ')}") unless fstab.empty?
    extra_bin = s.fetch("local_bin", []).reject { |l| l.end_with?(":") }
    rep.line("TODO", "Hand-installed software in /usr/local/bin or /opt: #{extra_bin.join(', ')}") unless extra_bin.empty?
    homes = s.fetch("home", [])
    rep.line("TODO", "Home directories to copy: #{homes.map { |h| "/home/#{h}" }.join(', ')}") unless homes.empty?
    config_txt = s.fetch("config_txt", [])
    unless config_txt.empty?
      rep.line("TODO", "/boot/firmware/config.txt has #{config_txt.size} active lines: compare them with the fresh " \
                       "image's file and re-apply your own (don't copy the whole file)")
    end

    rep.section("Known trixie changes (Debian 13 release notes, chapter 5)")
    sysctl = s.fetch("sysctl_conf", [])
    if sysctl.empty?
      rep.line("OK", "/etc/sysctl.conf has no active settings")
    else
      rep.line("WARN", "/etc/sysctl.conf is no longer read on trixie; move these to /etc/sysctl.d/*.conf: #{sysctl.join('; ')}")
    end
    pam = s.fetch("pam_environment", [])
    rep.line(pam.empty? ? "OK" : "WARN", pam.empty? ? "No ~/.pam_environment files" :
      "SSH no longer reads ~/.pam_environment (#{pam.join(', ')}): move the variables to the shell profile")
    dsa = s.fetch("dsa_keys", [])
    rep.line(dsa.empty? ? "OK" : "WARN", dsa.empty? ? "No DSA SSH keys" : "DSA keys stop working on trixie: #{dsa.join(', ')}")
    tmp = s.fetch("tmp_mb", ["0"]).first.to_i
    rep.line(tmp > 500 ? "WARN" : "OK", "/tmp holds #{tmp} MB; on trixie /tmp is in RAM (tmpfs, up to 50% of memory)")
    rep.line("INFO", "`last`, `lastb` and `lastlog` are gone (use `lslogins`); the `ping` and network-interface-name " \
                     "changes don't affect a Pi's eth0")
  end

  def boot_check(s, root, rep)
    order = s.fetch("boot_order", []).first.to_s[/0x([0-9a-f]+)/i, 1]
    unless order
      rep.line("INFO", "Boot order unknown (rpi-eeprom-config needs root): run `sudo rpi-eeprom-config | grep BOOT_ORDER`")
      return
    end
    modes = order.downcase.reverse.chars.filter_map { |c| BOOT_MODES[c] }
    rep.line("INFO", "Boot order (first to last): #{modes.join(' → ')}")
    current = root.include?("nvme") ? "NVMe" : root.include?("mmcblk") ? "SD card" : "USB"
    alt = modes.take_while { |m| m != current }.find { |m| ["SD card", "USB"].include?(m) }
    if alt
      rep.line("OK", "Safe test path: a trixie #{alt} boots before the current #{current} system. Insert it to test, " \
                     "remove it to return to the untouched #{current} install")
    else
      rep.line("TODO", "No SD/USB boot before #{current}: to test-boot trixie from a spare card, temporarily set " \
                       "BOOT_ORDER=0xf461 (SD first) with `sudo rpi-eeprom-config --edit`")
    end
  end

  def package_check(s, sources, third, rep)
    rep.section("Hand-installed packages vs trixie")
    manual = s.fetch("manual", [])
    names = Set.new
    [*DEBIAN_TRIXIE, RPI_TRIXIE].each do |url|
      idx = index_names(url)
      idx ? names.merge(idx) : rep.line("WARN", "Could not download #{url}")
    end
    third.each do |src|
      suite = src[:suite].sub("bookworm", "trixie")
      comps = src[:components].empty? ? ["main"] : src[:components]
      comps.each do |c|
        idx = index_names("#{src[:uri]}/dists/#{suite}/#{c}/binary-arm64/Packages.gz") ||
              index_names("#{src[:uri]}/dists/#{suite}/#{c}/binary-arm64/Packages")
        names.merge(idx) if idx
      end
    end
    return if names.empty?

    missing = manual.reject { |p| names.include?(p) || names.include?("#{p}t64") }
    renamed = manual.select { |p| !names.include?(p) && names.include?("#{p}t64") }
    rep.line("OK", "#{manual.size - missing.size} of #{manual.size} hand-installed packages exist on trixie")
    rep.line("INFO", "Renamed for the 64-bit time_t transition (apt handles this): #{renamed.join(', ')}") unless renamed.empty?
    return if missing.empty?

    rep.line("WARN", "Not in trixie (#{missing.size}): #{missing.join(', ')}. Usually replaced or renamed; " \
                     "check each with `apt-cache policy <pkg>` on the new system or packages.debian.org")
  end

  def pihole_check(s, rep)
    v = s.fetch("pihole", [])
    return if v.empty?

    rep.line("TODO", "Pi-hole (#{v.join(' / ')}): it supports maintained Raspberry Pi OS releases, so trixie works. " \
                     "Export Settings → Teleporter, reinstall with `curl -sSL https://install.pi-hole.net | bash`, " \
                     "import the Teleporter file. Keep the same IP (DHCP reservation)")
  end

  def vpn_check(s, rep)
    wg = s.fetch("wireguard", [])
    pivpn = s.fetch("pivpn", [])
    return if wg.empty? && pivpn.empty?

    detail = wg.empty? ? "" : " (configs: #{wg.join(', ')})"
    if pivpn.empty?
      rep.line("TODO", "WireGuard#{detail}: copy /etc/wireguard, install wireguard-tools, `systemctl enable wg-quick@<name>`")
    else
      rep.line("TODO", "PiVPN#{detail}: PiVPN 4.10.1+ installs on trixie, but the project is in best-effort maintenance. " \
                       "Lowest risk: copy /etc/wireguard (server key + peers) and run it with wireguard-tools' " \
                       "`wg-quick@wg0`; clients keep working unchanged")
    end
  end

  def docker_check(s, rep)
    lines = s.fetch("docker", [])
    return if lines.empty?

    split = lines.index("== mounts") || lines.size
    containers = lines[0...split].map { |l| l.split("|") }
    mounts = lines[(split + 1)..].to_a.flat_map { |l| l.split("|").drop(1) }
    binds = mounts.filter_map { |m| m.split(":", 2).last if m.start_with?("bind:") }.uniq
    volumes = mounts.count { |m| m.start_with?("volume:") }
    compose = containers.filter_map { |c| c[3] unless c[3].to_s.empty? }.flat_map { |f| f.split(",") }.uniq
    rep.line("TODO", "Docker: #{containers.size} containers (#{containers.map(&:first).join(', ')}). Install docker-ce " \
                     "from Docker's trixie repository, then copy and `docker compose up -d`")
    rep.line("TODO", "Compose files to copy: #{compose.join(', ')}") unless compose.empty?
    rep.line("TODO", "Bind-mounted data to copy: #{binds.join(', ')}") unless binds.empty?
    rep.line("TODO", "#{volumes} named volume mount(s): back up with `docker run --rm -v <vol>:/v -v $PWD:/b alpine tar czf /b/<vol>.tgz -C /v .`") if volumes.positive?
  end

  # ------------------------------------------------------------------------- CLI

  def main(argv)
    opts = {}
    OptionParser.new do |o|
      o.banner = "Usage: trixie_check.rb (--host USER@PI | --from FILE | --via CMD) [--no-packages]"
      o.on("--host TARGET", "collect over SSH, e.g. pi@192.168.1.2") { |v| opts[:host] = v }
      o.on("--from FILE", "analyse a saved inventory instead of collecting") { |v| opts[:from] = v }
      o.on("--via CMD", "run the collector through another command that reads a shell script on stdin " \
                        "(e.g. 'docker run -i --rm debian:bookworm sh -s')") { |v| opts[:via] = v }
      o.on("--no-packages", "skip downloading trixie package indexes (~15 MB)") { opts[:no_packages] = true }
    end.parse!(argv)
    abort "pass --host, --from or --via (see --help)" unless opts[:host] || opts[:from] || opts[:via]

    text, path = opts[:from] ? [File.read(opts[:from]), opts[:from]] : collect(opts)
    puts "Inventory: #{path.delete_prefix("#{ROOT}/")}"
    rep = Report.new
    analyse(text, rep, opts)
    rep.summary
    puts "\nBLOCK = something that has no trixie version yet. TODO = carry over during a fresh install. " \
         "Nothing was changed on the Pi."
    0
  end
end

if $PROGRAM_NAME == __FILE__
  $stdout.sync = true
  exit TrixieCheck.main(ARGV)
end
