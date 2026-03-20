# ICS Simulation Lab

This repository builds a small, segmented industrial control system lab on top of Incus. It is designed for local research, demonstrations, automation testing, packet capture exercises, and security validation. It is intentionally simple and portable. It is not a production ICS reference architecture.

The stack has three layers:

- OpenTofu creates the Incus project, bridges, base profile, and system containers.
- Ansible configures the guests and installs the simulated ICS services.
- Helper scripts generate inventory, validate the deployment, and optionally launch OCI application containers.

## Topology Schema

```text
                                   +----------------------+
                                   |      wan-test01      |
                                   |   198.18.110.10      |
                                   | WAN validation host  |
                                   +----------+-----------+
                                              |
                                  ics-wan     |
                              198.18.110.0/24 |
                                              |
                                   +----------+-----------+
                                   |         fw01         |
                                   |  Router / Firewall   |
                                   | DNS / NAT / Gateway  |
                                   | .110.254 .10.254     |
                                   | .20.254  .30.254     |
                                   | .40.254              |
                                   +---+---------+--------+
                                       |         |
                     +-----------------+         +--------------------+
                     |                                            ics-ot-dmz
                     | ics-it                                     198.18.20.0/24
                     | 198.18.10.0/24                                  |
                     |                                                  |
     +---------------+---------------+                   +--------------+--------------+
     |               |               |                   |                             |
+----+-----+   +-----+-----+   +-----+------+      +-----+------+               +------+------+
| it-file01|   | it-ws01   |   |it-activity01|      |otdmz-jump01|               |  mqtt01*    |
| SMB file |   | test host |   | sample user |      | SSH pivot   |               | optional    |
| server    |   | / tooling |   | activity    |      | host        |               | MQTT broker |
+----------+   +-----------+   +-------------+      +------------+               +-------------+

                                                                  DMZ -> OPS: tcp/22,443
                                                                  OPS -> DMZ: tcp/1883

                                                        ics-ot-ops 198.18.30.0/24
                                                                    |
                                         +--------------------------+--------------------------+
                                         |                                                     |
                                   +-----+------+                                       +------+------+
                                   |otops-scada01|                                       | otops-hmi01 |
                                   | SCADA poller|                                       | HMI web UI  |
                                   | API :8081   |                                       | Web :8080   |
                                   +-----+------+                                       +------+------+
                                         |
                                         | OPS -> CELL: tcp/502
                                         |
                                 ics-ot-cell 198.18.40.0/24
                                         |
                         +---------------+----------------+
                         |                                |
                   +-----+------+                   +-----+------+
                   |otcell-plc01|                   |otcell-     |
                   | PLC sim     |<--- HTTP :8080 --|process01   |
                   | Modbus :502 |                   | tank model |
                   +------------+                   +------------+
```

`*` Optional OCI containers are not part of the default base deployment.

## What The Lab Simulates

At runtime, the lab models a small OT stack with a simple process loop:

1. `otcell-process01` simulates a tank process and exposes its state over HTTP.
2. `otcell-plc01` polls that process over HTTP, converts the values into registers, and serves them over Modbus/TCP on port `502`.
3. `otops-scada01` polls the PLC over Modbus/TCP, scales the register values into tags, and exposes them through a small HTTP API.
4. `otops-hmi01` renders a browser-based dashboard that fetches tag data from the SCADA API every two seconds.

The core data path is:

```text
Process HTTP -> PLC Modbus/TCP -> SCADA API -> HMI
```

The network policy intentionally prevents most direct shortcuts between zones, so the interesting traffic follows controlled north-south paths through `fw01`.

## Segmentation Model

The default deployment creates five routed segments:

- `ics-wan`: `198.18.110.0/24`
- `ics-it`: `198.18.10.0/24`
- `ics-ot-dmz`: `198.18.20.0/24`
- `ics-ot-ops`: `198.18.30.0/24`
- `ics-ot-cell`: `198.18.40.0/24`

`fw01` is the only node attached to every segment. It provides:

- inter-zone routing
- default gateway service for internal segments
- outbound source NAT toward the WAN bridge
- DNS forwarding through `dnsmasq`
- inter-zone filtering through `nftables`

The firewall policy is deny-by-default between zones, with these explicit allows:

- IT -> DMZ: `tcp/22`
- DMZ -> OPS: `tcp/22`, `tcp/443`
- OPS -> CELL: `tcp/502`
- OPS -> DMZ: `tcp/1883`
- Internal zones -> WAN: allowed and source-NATed on `fw01`
- WAN -> internal zones: dropped

Important detail:

- `DMZ -> OPS tcp/443` is allowed at the firewall even though the base lab does not expose a service there by default.
- `OPS -> DMZ tcp/1883` is allowed so an optional MQTT broker such as `mqtt01` can be added later.

The current live validation should look like this:

- IT can reach the jump host over SSH.
- IT cannot directly reach OPS or CELL services.
- SCADA in OPS can reach the PLC in CELL on `502`.
- WAN cannot directly initiate connections into IT, DMZ, OPS, or CELL.

## Default Containers And Their Purpose

The base lab deploys one Incus project named `ICS-simulation`, five bridges, and ten system containers.

### `fw01`

Purpose:

- router
- firewall
- DNS forwarder
- outbound NAT gateway

What runs there:

- `nftables`
- `dnsmasq`
- SSH

Why it matters:

- It is the main packet capture point for routed inter-zone traffic.
- It enforces the lab segmentation policy.

### `wan-test01`

Purpose:

- WAN-side validation host
- used to prove that inbound traffic is blocked

What is installed there:

- troubleshooting tools from Ansible such as `ping`, `traceroute`, and `tcpdump`

Why it matters:

- It gives you an external-looking vantage point for testing exposure.

### `it-file01`

Purpose:

- SMB file server for the IT zone

What runs there:

- Samba

What it exposes:

- `Engineering`
- `Operations`
- `Backups`

Why it matters:

- It gives the lab a simple business-side service and a place for file-oriented exercises.

### `it-ws01`

Purpose:

- IT workstation and generic test client

What is installed there:

- troubleshooting tools
- `smbclient`
- `tcpdump`

Why it matters:

- It is the easiest place to exercise IT-to-DMZ and blocked IT-to-OT paths.

### `it-activity01`

Purpose:

- sample activity runner host

What is installed there:

- `/opt/ics/activity/activity_runner.py`
- `/opt/ics/activity/scenario.yaml`

Why it matters:

- It provides repeatable operator-style or validation-style actions without needing a browser.

### `otdmz-jump01`

Purpose:

- SSH landing point in the OT DMZ

What is installed there:

- SSH client tooling

Why it matters:

- It is the intended first hop from IT into the OT side.

### `otops-scada01`

Purpose:

- SCADA poller
- tag normalizer
- API server for downstream consumers

What runs there:

- `/opt/ics/scada/scada_api.py`
- systemd unit `ics-scada.service`

What it does:

- polls the PLC on `198.18.40.10:502`
- scales raw register values into tags
- optionally checks whether an MQTT broker is reachable
- serves tag state over HTTP on port `8081`

### `otops-hmi01`

Purpose:

- web-based HMI

What runs there:

- `/opt/ics/hmi/hmi_server.py`
- systemd unit `ics-hmi.service`

What it does:

- serves the HMI page on `198.18.30.20:8080`
- proxies current SCADA tag data at `/api/tags`
- refreshes the page data every two seconds

### `otcell-plc01`

Purpose:

- PLC simulator

What runs there:

- `/opt/ics/plc/plc_sim.py`
- systemd unit `ics-plc.service`

What it does:

- polls the process simulator over HTTP
- stores register values in `/var/lib/ics-plc/state.json`
- exposes Modbus/TCP on port `502`
- accepts selected write operations that change process setpoint or pump state

### `otcell-process01`

Purpose:

- process simulator

What runs there:

- `/opt/ics/process/tank_process.py`
- systemd unit `ics-process.service`

What it does:

- simulates a tank level drifting around a setpoint
- updates inlet flow, outlet flow, alarms, and pump state every second
- serves the current process state over HTTP on port `8080`
- accepts JSON commands on `/command`

## Optional OCI Containers

The helper script `scripts/oci_deploy.sh` can add OCI application containers:

- `mqtt01` in `ics-ot-dmz`
- `influxdb01` in `ics-ot-ops` when `DEPLOY_OBSERVABILITY=1`
- `grafana01` in `ics-ot-ops` when `DEPLOY_OBSERVABILITY=1`

These are optional extensions, not part of the default base lab. Some OCI images need static interface bootstrapping when attached to non-DHCP bridges. `scripts/oci-wrapper.sh` is included for that case.

## How The Simulated Process Works

The process model in `tank_process.py` is intentionally small and readable.

- Initial state starts near a 52 percent tank level with a 55 percent setpoint.
- Every second, the process calculates a new inlet flow and outlet flow.
- If the level falls well below the setpoint, the pump runs.
- If the level rises well above the setpoint, the pump stops.
- High and low alarms become active near the limits.

The HTTP API on `otcell-process01` provides:

- `GET /state`: current process state
- `GET /health`: service health
- `POST /command`: apply updates such as `setpoint_pct` or `pump_running`

Example:

```bash
curl http://198.18.40.20:8080/state
curl -X POST http://198.18.40.20:8080/command \
  -H 'Content-Type: application/json' \
  -d '{"setpoint_pct": 60.0}'
```

## How The PLC Simulation Works

The PLC simulator is a small Modbus/TCP service.

- It polls the process state API every two seconds.
- It writes those values into an internal register bank.
- It marks a health register to show whether the upstream process poll succeeded.
- It exposes the register bank over Modbus function code `3`.
- It accepts selected Modbus function code `6` writes and forwards them to the process API.

State is persisted to:

- `/var/lib/ics-plc/state.json`

Useful live checks:

```bash
incus exec --project ICS-simulation otcell-plc01 -- systemctl status ics-plc
incus exec --project ICS-simulation otcell-plc01 -- cat /var/lib/ics-plc/state.json
```

## How The SCADA Service Works

The SCADA service is a poller plus a small HTTP API.

- It opens a TCP connection to the PLC every polling cycle.
- It reads holding registers from the PLC.
- It scales the raw register values into named tags.
- It publishes the current tag snapshot at `/api/tags`.
- It records whether an optional MQTT broker is reachable.

The SCADA API provides:

- `GET /api/tags`
- `GET /`
- `GET /health`

Example:

```bash
curl http://198.18.30.10:8081/api/tags
```

## How The HMI Works

The HMI is intentionally thin.

- The root page `/` serves a static HTML dashboard.
- The page fetches `/api/tags` every two seconds.
- The HMI server then fetches data from the SCADA API.
- Cards are colored to make healthy values and alarm conditions easier to spot.

Example:

```bash
curl http://198.18.30.20:8080/
curl http://198.18.30.20:8080/api/tags
```

## How The Activity Simulation Works

`it-activity01` contains a sample scenario runner for repeatable validation steps. It is not a scheduler by default. It runs when you execute it.

The sample scenario currently does three things:

1. confirms that IT can SSH to the jump host
2. confirms that IT cannot directly reach the PLC
3. sleeps for two seconds

Run it like this:

```bash
incus exec --project ICS-simulation it-activity01 -- \
  python3 /opt/ics/activity/activity_runner.py
```

Or point it at another scenario:

```bash
incus exec --project ICS-simulation it-activity01 -- \
  python3 /opt/ics/activity/activity_runner.py --scenario /path/to/scenario.yaml
```

Supported sample actions are:

- `sleep`
- `tcp_check`
- `http_get`

This makes the activity runner useful for:

- smoke-style validation
- repeatable classroom demos
- generating simple known-good traffic before a packet capture

## Deploy The Lab

### Prerequisites

- Incus installed and initialized
- OpenTofu available as `tofu`
- Ansible available as `ansible-playbook`
- Python 3 available as `python3`
- an existing Incus storage pool
- an SSH public key for the `lab` user

### Required Variables

Provide these OpenTofu variables through `infra/terraform.tfvars`, environment variables, or `-var` flags:

- `storage_pool`
- `image_debian_cloud`
- `image_ubuntu_cloud`
- `ssh_public_key`

The base deployment uses the Debian cloud image for all system containers. The Ubuntu image variable is present for optional extensions and OCI wrapper patterns.

### End-To-End Deployment

From the repository root:

```bash
cd infra
tofu init
tofu apply
tofu output -json > ../infra_outputs.json
cd ..

python3 scripts/generate_inventory.py

cd ansible
ansible-playbook site.yml
cd ..

bash scripts/oci_deploy.sh
bash scripts/smoke_test.sh
```

Recommended rule:

- treat OpenTofu as infrastructure provisioning
- treat Ansible as guest convergence
- re-run Ansible after recreating or replacing containers

## How To Use The Lab

### Enter A Container

```bash
incus exec --project ICS-simulation it-ws01 -- bash
incus exec --project ICS-simulation otops-scada01 -- bash
incus exec --project ICS-simulation otcell-plc01 -- bash
```

### SSH Into A Host

```bash
ssh lab@198.18.10.20
ssh lab@198.18.20.10
ssh lab@198.18.30.10
```

### Validate Segmentation

Expected examples:

```bash
incus exec --project ICS-simulation it-ws01 -- nc -zvw3 198.18.20.10 22
incus exec --project ICS-simulation it-ws01 -- nc -zvw3 198.18.40.10 502
incus exec --project ICS-simulation otops-scada01 -- nc -zvw3 198.18.40.10 502
incus exec --project ICS-simulation wan-test01 -- nc -zvw3 198.18.10.20 22
```

Expected outcome:

- IT can reach DMZ SSH
- IT cannot directly reach the PLC
- SCADA can reach the PLC
- WAN cannot initiate traffic toward internal zones

### Inspect The Application Layer

```bash
curl http://198.18.40.20:8080/state
curl http://198.18.30.10:8081/api/tags
curl http://198.18.30.20:8080/
```

### Observe Service State

```bash
incus exec --project ICS-simulation otcell-process01 -- systemctl status ics-process
incus exec --project ICS-simulation otcell-plc01 -- systemctl status ics-plc
incus exec --project ICS-simulation otops-scada01 -- systemctl status ics-scada
incus exec --project ICS-simulation otops-hmi01 -- systemctl status ics-hmi
```

### Capture Packets

Good capture points depend on your question:

- `fw01`: best single vantage point for routed inter-zone traffic
- `otops-scada01`: best place to observe SCADA-to-PLC Modbus sessions
- `otcell-plc01` or `otcell-process01`: best place to observe local HTTP traffic inside the cell
- `it-ws01`: useful for validating IT-side reachability and SMB traffic
- `wan-test01`: useful for validating blocked inbound traffic from the WAN side

Examples:

```bash
incus exec --project ICS-simulation fw01 -- tcpdump -ni eth4 tcp port 502
incus exec --project ICS-simulation otcell-plc01 -- tcpdump -ni eth0 host 198.18.40.20
```

If you replace a container and have not re-run Ansible yet, packet capture tools may not be present on that host.

## Validation And Troubleshooting

### Smoke Test

The bundled smoke test checks:

- IT -> DMZ SSH is allowed
- IT -> CELL `502` is blocked
- OPS -> CELL `502` is allowed
- optional MQTT reachability if `mqtt01` exists
- SCADA API availability
- HMI page availability

Run it with:

```bash
bash scripts/smoke_test.sh
```

### Common Operator Checks

```bash
incus list --project ICS-simulation
incus exec --project ICS-simulation fw01 -- sudo nft list ruleset
incus exec --project ICS-simulation fw01 -- ip -br a
incus exec --project ICS-simulation otops-scada01 -- ss -ltnp
incus exec --project ICS-simulation otcell-process01 -- curl -s http://127.0.0.1:8080/state
```

### Re-Apply Guest Configuration

If you change Ansible files or recreate a host:

```bash
cd ansible
ansible-playbook site.yml
```

## Repository Structure

This repository is small enough that every top-level directory has a clear purpose.

### `infra/`

OpenTofu code that creates the project, bridges, profile, and instances.

- `main.tf`: creates the Incus project, bridges, base profile, `fw01`, and the remaining lab nodes
- `locals.tf`: defines the topology, host inventory, static IPs, packages, and cloud-init content
- `variables.tf`: declares the required inputs
- `versions.tf`: pins Terraform and provider requirements
- `outputs.tf`: exports project name and host metadata
- `terraform.tfvars`: local variable values for the deployment
- `templates/cloud-init-network-config.tftpl`: renders static interface config
- `templates/cloud-init-user-data.tftpl`: renders users, packages, files, and boot commands

### `ansible/`

Guest configuration and simulated service deployment.

- `site.yml`: main playbook
- `ansible.cfg`: inventory path, roles path, and SSH defaults
- `group_vars/all.yml`: shared service endpoints, addresses, and port values
- `inventory/inventory.yml`: generated inventory file created by `scripts/generate_inventory.py`

#### `ansible/roles/`

Each role manages one functional part of the lab.

- `router_firewall/`: `nftables`, `dnsmasq`, IP forwarding
- `file_server/`: Samba shares and configuration
- `activity_agent/`: sample scenario and runner
- `process_sim/`: tank process simulator and systemd unit
- `plc_sim/`: PLC simulator and systemd unit
- `scada_host/`: SCADA poller/API and systemd unit
- `hmi_host/`: HMI server and systemd unit

Inside each role:

- `tasks/main.yml` defines the install and converge steps
- `files/` contains shipped scripts or static assets
- `templates/` contains Jinja templates for service units and configs

### `scripts/`

Helper tooling for provisioning and validation.

- `generate_inventory.py`: converts `infra_outputs.json` into `ansible/inventory/inventory.yml`
- `wait_for_cloud_init.sh`: blocks until cloud-init is ready on a target instance
- `smoke_test.sh`: validates the expected basic connectivity and service behavior
- `oci_deploy.sh`: launches optional OCI app containers into the lab
- `oci-wrapper.sh`: helper entrypoint for OCI images that need static IP or gateway setup

## How The Tools Fit Together

The expected workflow is:

1. use OpenTofu to create the Incus project, networks, and containers
2. export OpenTofu outputs
3. generate the Ansible inventory from those outputs
4. run Ansible to converge the guest operating systems and services
5. optionally deploy OCI add-ons
6. validate the result with smoke tests and manual checks

In short:

- Incus provides the container runtime and bridges
- OpenTofu describes infrastructure state
- Ansible describes guest configuration state
- Python service files implement the simulated ICS behavior
- shell and Python helper scripts glue the workflow together

## Notes

- All system containers use cloud-init.
- A `lab` user is created with passwordless sudo and the supplied SSH key.
- Static addressing is defined through cloud-init network config.
- The deployment is intended to be re-runnable.
- If you replace a container with OpenTofu, re-run Ansible so host tooling and services are restored to the expected state.

## Safety Notice

This lab deliberately simplifies industrial protocols, host behavior, and segmentation details to stay understandable and portable. Use it for research and education, not as a blueprint for production control systems.
