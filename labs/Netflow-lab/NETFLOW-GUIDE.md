# NetFlow Monitoring - Complete Guide

## 1. What is NetFlow?

**NetFlow** is a network protocol developed by Cisco for collecting IP traffic information and monitoring network traffic. It provides detailed information about network flows, which are unidirectional sequences of packets sharing common characteristics.

### Key Concepts:

- **Flow**: A unidirectional stream of packets between a source and destination
  - Defined by: Source IP, Destination IP, Source Port, Destination Port, Protocol, Interface
  
- **Flow Exporter**: Device that monitors traffic and sends flow records (in our case: **softflowd** on Router-Firewall)

- **Flow Collector**: System that receives and stores flow data (in our case: **nfcapd** on NetFlow-Collector)

- **Flow Analyzer**: Tool to analyze collected data (in our case: **nfdump** command-line tool)

### What Information Does NetFlow Capture?

Each flow record contains:
- Source and destination IP addresses
- Source and destination ports
- Protocol (TCP, UDP, ICMP, etc.)
- Number of packets and bytes
- Timestamps (start and end time)
- Input/output interfaces
- TCP flags

### NetFlow Versions:

- **NetFlow v5**: Original version, IPv4 only
- **NetFlow v9**: Template-based, extensible (we use this)
- **IPFIX**: International standard based on NetFlow v9

---

## 2. How to Use NetFlow and Why?

### Why Use NetFlow?

#### **Security Monitoring**:
- Detect anomalous traffic patterns
- Identify port scans and network reconnaissance
- Detect DDoS attacks
- Track lateral movement in the network
- Identify data exfiltration attempts

#### **Network Performance**:
- Identify bandwidth hogs
- Monitor application usage
- Analyze traffic patterns
- Capacity planning

#### **Troubleshooting**:
- Identify connectivity issues
- Track routing problems
- Analyze slow network performance

#### **Compliance**:
- Network traffic auditing
- Record keeping for regulatory requirements

### How to Use NetFlow?

#### **Basic Workflow**:

1. **Generate Traffic** → Traffic flows through the router
2. **Export Flows** → softflowd captures packets and exports flow records every 60 seconds
3. **Collect Flows** → nfcapd receives and stores flows in 5-minute files
4. **Analyze Flows** → Use nfdump to query and analyze the data

---

## 3. How to Create Rules and Filters?

### Understanding nfdump Filter Syntax

nfdump uses a powerful filter language to query flow data.

### Basic Filter Examples:

#### **Filter by IP Address**:
```bash
# Show flows from a specific source IP
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76'

# Show flows to a specific destination IP
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'dst ip 8.8.8.8'

# Show flows involving a specific IP (source OR destination)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'ip 198.18.200.76'
```

#### **Filter by Network**:
```bash
# Show flows from LAN network
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src net 198.18.200.0/24'

# Show flows to external networks (not LAN)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'dst net 0.0.0.0/0 and not dst net 198.18.200.0/24'
```

#### **Filter by Port**:
```bash
# Show HTTP traffic
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'port 80'

# Show HTTPS traffic
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'port 443'

# Show SSH traffic
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'port 22'

# Show traffic on specific destination port
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'dst port 443'
```

#### **Filter by Protocol**:
```bash
# Show TCP traffic only
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'proto tcp'

# Show UDP traffic only
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'proto udp'

# Show ICMP traffic (ping)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'proto icmp'
```

#### **Combine Multiple Filters**:
```bash
# Show HTTPS traffic from Attacker-internal
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76 and dst port 443'

# Show all traffic EXCEPT DNS
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'not port 53'

# Show suspicious port scan activity (many different destination ports)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76 and flags S and packets < 5'
```

### Advanced Filtering:

#### **Filter by Bytes/Packets**:
```bash
# Show large flows (> 1MB)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'bytes > 1000000'

# Show small flows (potential scans)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'packets < 10'
```

#### **Filter by TCP Flags**:
```bash
# Show SYN packets (connection attempts)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'flags S'

# Show RST packets (connection resets)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'flags R'
```

#### **Filter by Time**:
```bash
# Show flows from specific time range
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -t 2026/01/23.14:00:00-2026/01/23.15:00:00
```

---

## 4. How to Capture Traffic and Analyze with nfdump?

### Complete Testing Workflow

#### **Step 1: Generate Traffic**

Traffic flows through your Router-Firewall automatically, but you can generate specific traffic for testing:

```bash
# ICMP traffic (ping)
incus exec Attacker-internal -- ping -c 50 8.8.8.8

# DNS queries
incus exec Attacker-internal -- nslookup google.com

# Multiple pings to different destinations
incus exec Attacker-internal -- bash -c "ping -c 20 1.1.1.1 && ping -c 20 8.8.4.4"

# Generate continuous traffic
incus exec Attacker-internal -- ping -c 100 8.8.8.8
```

#### **Step 2: Wait for Flow Export**

**Important timing to understand**:
- softflowd exports flows after **60 seconds** of inactivity (maxlife parameter)
- OR when the flow ends (TCP FIN/RST packets)
- nfcapd rotates files every **5 minutes** (300 seconds)

**Best practice**: Wait at least **65 seconds** after traffic stops before checking for flows.

```bash
# Wait for flows to be exported
echo "Waiting 65 seconds for flows to be exported..."
sleep 65
```

#### **Step 3: Verify Flow Collection**

```bash
# Check if flows were collected
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10

# Check file creation
incus exec NetFlow-Collector -- ls -lh /var/cache/nfdump/

# View overall statistics
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -I
```

#### **Complete Example Workflow**:

```bash
# 1. Generate traffic
incus exec Attacker-internal -- ping -c 30 8.8.8.8

# 2. Wait for export
echo "Waiting 65 seconds for flows to be exported..."
sleep 65

# 3. Check if flows were collected
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10

# 4. Filter to see just the ICMP traffic
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'proto icmp' -o extended

# 5. See detailed statistics
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -I
```

### Understanding nfdump Output

When you run nfdump, you'll see output like:
```
Date first seen          Duration Proto   Src IP Addr:Port    Dst IP Addr:Port   Packets    Bytes
2026-01-23 14:26:57.501  00:01:17 ICMP    198.18.200.78:0  ->  8.8.8.8:8.0        2285      310213
```

This tells you:
- **When**: Flow started at 14:26:57
- **How long**: Lasted 1 minute 17 seconds
- **What**: ICMP protocol (ping)
- **Who**: From 198.18.200.78 to 8.8.8.8
- **How much**: 2285 packets, 310KB of data

### Essential nfdump Commands:

#### **1. View Top Talkers (Most Active IPs)**:

```bash
# Top 10 source IPs by bytes transferred
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10

# Top 10 destination IPs by bytes
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s dstip/bytes -n 10

# Top 10 source IPs by packet count
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/packets -n 10
```

#### **2. View Top Protocols**:

```bash
# Top protocols by bytes
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s proto/bytes -n 10
```

#### **3. View Top Ports**:

```bash
# Top destination ports (services being accessed)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s dstport/bytes -n 20

# Top source ports
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcport/bytes -n 20
```

#### **4. View All Flows (Detailed)**:

```bash
# Show all flows with extended information
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o extended

# Show flows in a specific format
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o "fmt:%ts %td %pr %sap -> %dap %pkt %byt %fl"
```

#### **5. View Flows from Specific Host**:

```bash
# All traffic from Attacker-internal (198.18.200.76)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76' -o extended

# Top destinations contacted by Attacker-internal
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76' -s dstip/bytes -n 10
```

#### **6. Real-Time Monitoring**:

```bash
# Watch for new flows (check every 10 seconds)
watch -n 10 'incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10'
```

#### **7. Export to CSV for Analysis**:

```bash
# Export flows to CSV format
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o csv > flows.csv
```

### Useful Statistics Commands:

```bash
# Overall statistics
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -I

# Statistics by protocol
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s proto/bytes

# Statistics by source IP
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/flows -n 20
```

### Security Analysis Examples:

#### **Detect Port Scans**:
```bash
# Find hosts connecting to many different ports
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/dstport -n 20
```

#### **Detect Data Exfiltration**:
```bash
# Find large outbound transfers
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src net 198.18.200.0/24 and bytes > 10000000' -s srcip/bytes
```

#### **Detect Suspicious DNS Activity**:
```bash
# Show all DNS queries
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'port 53' -o extended
```

#### **Detect Lateral Movement**:
```bash
# Show internal-to-internal traffic
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src net 198.18.200.0/24 and dst net 198.18.200.0/24'
```

---

## 5. How We Configured It?

### Architecture Overview:

```
┌─────────────────────┐
│  Router-Firewall    │
│  198.18.200.10      │
│                     │
│  ┌───────────────┐  │
│  │  softflowd    │  │──┐
│  │  (eth0+eth1)  │  │  │ NetFlow v9
│  └───────────────┘  │  │ UDP:2055
└─────────────────────┘  │
                         │
                         ▼
┌─────────────────────────────────┐
│  NetFlow-Collector              │
│  198.18.200.20                  │
│                                 │
│  ┌──────────┐   ┌────────────┐ │
│  │  nfcapd  │──▶│  nfdump    │ │
│  │ UDP:2055 │   │ (analysis) │ │
│  └──────────┘   └────────────┘ │
│                                 │
│  Storage: /var/cache/nfdump/   │
└─────────────────────────────────┘
         │
         │ HTTP:80 (proxied to localhost:8080)
         ▼
    Your Browser
```

### Components:

#### **1. Flow Exporter: softflowd (on Router-Firewall)**

**What it does**: Monitors network interfaces and exports flow records

**Configuration**:
- **Two separate instances**: One for eth0 (WAN), one for eth1 (LAN)
- **Export destination**: 198.18.200.20:2055 (NetFlow-Collector)
- **NetFlow version**: v9
- **Flow timeout**: 60 seconds (maxlife parameter)

**Systemd services**:
- `softflowd-eth0.service` - Monitors WAN interface
- `softflowd-eth1.service` - Monitors LAN interface

**Command**:
```bash
/usr/sbin/softflowd -i eth0 -n 198.18.200.20:2055 -v 9 -t maxlife=60 -d -p /var/run/softflowd-eth0.pid -c /var/run/softflowd-eth0.ctl
```

**Why two instances?**: softflowd can only monitor ONE interface per process.

#### **2. Flow Collector: nfcapd (on NetFlow-Collector)**

**What it does**: Receives NetFlow packets and stores them in binary files

**Configuration**:
- **Listen port**: UDP 2055
- **Storage directory**: /var/cache/nfdump/
- **File rotation**: Every 5 minutes (300 seconds)
- **User**: www-data

**Systemd service**: `nfcapd.service`

**Command**:
```bash
/usr/bin/nfcapd -w /var/cache/nfdump -p 2055 -t 300
```

**File naming**: `nfcapd.YYYYMMDDhhmm` (e.g., `nfcapd.202601231430`)

#### **3. Flow Analyzer: nfdump (on NetFlow-Collector)**

**What it does**: Reads and analyzes flow data from nfcapd files

**Usage**: Command-line tool with powerful filtering and aggregation

### Deployment Process:

#### **Step 1: Infrastructure Deployment**

```bash
cd lab
tofu apply -auto-approve
```

This creates:
- NetFlow-Collector container (198.18.200.20)
- Router-Firewall container (198.18.200.10)
- All other lab containers

#### **Step 2: Automatic Configuration (via cloud-init)**

**On Router-Firewall**:
1. Install softflowd package
2. Create two systemd service files (softflowd-eth0, softflowd-eth1)
3. Enable and start both services
4. Begin exporting flows immediately

**On NetFlow-Collector**:
1. Install nfdump, apache2, and dependencies
2. Create custom nfcapd systemd service
3. **Disable default nfdump service** (prevents port conflict)
4. Start custom nfcapd service on UDP:2055
5. Create storage directory: /var/cache/nfdump/
6. Set permissions for www-data user

#### **Step 3: Verification**

Wait 2-5 minutes for cloud-init to complete, then verify:

```bash
# Check nfcapd is running
incus exec NetFlow-Collector -- systemctl status nfcapd

# Check softflowd exporters are running
incus exec Router-Firewall -- systemctl status softflowd-eth0 softflowd-eth1

# Check for collected flows (after generating traffic)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10
```

### Key Configuration Details:

#### **Port Conflict Resolution**

**Problem**: Debian's nfdump package includes a default systemd service that auto-starts on port 2055.

**Solution**: Disable and mask the default service before starting our custom service:

```yaml
runcmd:
  - systemctl stop nfdump.service || true
  - systemctl disable nfdump.service || true
  - systemctl mask nfdump.service || true
  - systemctl enable --now nfcapd.service
```

This ensures only ONE nfcapd process runs, preventing "Address already in use" errors.

#### **Network Configuration**

**NetFlow-Collector** has a static IP (198.18.200.20) configured via cloud-init network-config:

```yaml
version: 2
ethernets:
  eth0:
    dhcp4: false
    addresses:
      - 198.18.200.20/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.200.10
    nameservers:
      addresses: [198.18.200.10]
```

---

## Practical Examples and Use Cases

### Example 1: Monitoring an Attack Scenario

**Scenario**: Attacker-internal (198.18.200.76) performs reconnaissance and attacks.

#### **Step 1: Generate Attack Traffic**

```bash
# Port scan from attacker
incus exec Attacker-internal -- nmap -p 1-1000 198.18.200.90

# Generate web traffic
incus exec Attacker-internal -- ping -c 100 8.8.8.8
```

#### **Step 2: Wait for Flow Export**

Wait 65+ seconds for softflowd to export flows (60-second timeout + processing time).

#### **Step 3: Analyze the Attack**

```bash
# See all activity from the attacker
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76' -o extended

# Detect port scan (many different destination ports)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76' -s dstport -n 50

# Find connection attempts (SYN packets)
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76 and flags S'
```

### Example 2: Bandwidth Monitoring

```bash
# Find top bandwidth consumers
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10

# Find which services use most bandwidth
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s dstport/bytes -n 20

# Monitor specific host's bandwidth
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'ip 198.18.200.76' -s bytes
```

### Example 3: Compliance and Auditing

```bash
# Show all external connections from LAN
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src net 198.18.200.0/24 and not dst net 198.18.200.0/24' -o extended

# Export to CSV for reporting
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o csv > /tmp/flows_report.csv
```

---

## Troubleshooting

### Issue: No Flows Being Collected

**Check 1: Is nfcapd running?**
```bash
incus exec NetFlow-Collector -- systemctl status nfcapd
incus exec NetFlow-Collector -- netstat -ulnp | grep 2055
```

**Check 2: Are softflowd exporters running?**
```bash
incus exec Router-Firewall -- systemctl status softflowd-eth0 softflowd-eth1
```

**Check 3: Are flows being exported?**
```bash
incus exec Router-Firewall -- softflowctl -c /var/run/softflowd-eth0.ctl statistics
```

**Check 4: Are NetFlow packets arriving?**
```bash
incus exec NetFlow-Collector -- tcpdump -ni eth0 udp port 2055 -c 10
```

**Check 5: Check nfcapd logs**
```bash
incus exec NetFlow-Collector -- journalctl -u nfcapd -n 50
```

### Issue: Port Conflict (Address Already in Use)

**Symptom**: nfcapd fails to start with "bind: Address already in use"

**Solution**: The default nfdump service is running. Disable it:

```bash
incus exec NetFlow-Collector -- bash -c "
  systemctl stop nfdump.service
  systemctl disable nfdump.service
  systemctl mask nfdump.service
  systemctl restart nfcapd
"
```

This is already fixed in the Terraform configuration.

### Issue: Flows Not Appearing Immediately

**This is normal!** Flow collection has delays:

1. **softflowd timeout**: 60 seconds (flows exported after 60s of inactivity or maxlife)
2. **nfcapd rotation**: 5 minutes (files rotated every 300 seconds)
3. **Processing time**: A few seconds

**Total delay**: Up to 65 seconds for flows to appear after traffic stops.

**Solution**: Generate continuous traffic or wait for the timeout period.

### Troubleshooting "No flows" Issue:

If you see "No matching flows", check:

```bash
# 1. Are files being created?
incus exec NetFlow-Collector -- ls -lh /var/cache/nfdump/

# 2. Is nfcapd running?
incus exec NetFlow-Collector -- systemctl status nfcapd

# 3. Are exporters running?
incus exec Router-Firewall -- systemctl status softflowd-eth0 softflowd-eth1

# 4. Are flows being exported from softflowd?
incus exec Router-Firewall -- softflowctl -c /var/run/softflowd-eth0.ctl statistics
incus exec Router-Firewall -- softflowctl -c /var/run/softflowd-eth1.ctl statistics

# 5. Are NetFlow packets arriving at collector?
incus exec NetFlow-Collector -- timeout 10 tcpdump -ni eth0 udp port 2055 -c 5
```

---

## Quick Reference Card

### Most Useful Commands:

```bash
# Top talkers
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s srcip/bytes -n 10

# View all flows
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o extended

# Filter by IP
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'src ip 198.18.200.76'

# Filter by port
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump 'port 443'

# Top protocols
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s proto/bytes

# Top ports
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -s dstport/bytes -n 20

# Statistics
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -I

# Export to CSV
incus exec NetFlow-Collector -- nfdump -R /var/cache/nfdump -o csv > flows.csv
```

### Service Management:

```bash
# Check collector status
incus exec NetFlow-Collector -- systemctl status nfcapd

# Check exporter status
incus exec Router-Firewall -- systemctl status softflowd-eth0 softflowd-eth1

# Restart collector
incus exec NetFlow-Collector -- systemctl restart nfcapd

# View logs
incus exec NetFlow-Collector -- journalctl -u nfcapd -f
```

### File Locations:

- **Flow data**: `/var/cache/nfdump/` on NetFlow-Collector
- **nfcapd service**: `/etc/systemd/system/nfcapd.service`
- **softflowd services**: `/etc/systemd/system/softflowd-eth0.service` and `softflowd-eth1.service`
- **Logs**: `journalctl -u nfcapd` or `journalctl -u softflowd-eth0`

---
