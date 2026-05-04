# Labs

This folder contains infrastructure-as-code labs used to deploy training environments with OpenTofu and Incus.

The goal is simple:

- use OpenTofu to declare the lab infrastructure
- use Incus to run the containers and virtual machines
- keep each lab in its own folder with its own documentation when needed

## Technologies used

- [OpenTofu](https://opentofu.org/docs/intro/) for infrastructure as code
- [Incus](https://linuxcontainers.org/incus/docs/main/general/) for containers, virtual machines, networking, and projects
- `cloud-init` user-data inside the OpenTofu definitions to configure instances at first boot
- Ansible in some labs, such as `ICS-Simulation`, for post-deployment configuration

Most labs in this folder use the `lxc/incus` provider from OpenTofu.

## Requirements

Before deploying a lab, make sure your host is ready:

1. Install OpenTofu:
   [Installing OpenTofu](https://opentofu.org/docs/intro/install/)
2. Install Incus:
   [How to install Incus](https://linuxcontainers.org/incus/docs/main/installing/)
3. Initialize Incus on your host:
   [How to initialize Incus](https://linuxcontainers.org/incus/docs/main/howto/initialize/)
4. If you are new to Incus, the official first-step guide is useful:
   [First steps with Incus](https://linuxcontainers.org/incus/docs/main/tutorial/first_steps/)

Practical notes:

- your user should be allowed to manage Incus, typically through the `incus-admin` group
- some labs create virtual machines as well as containers, so VM support must be enabled on the Incus host
- some current lab definitions expect an Incus storage pool named `incus-storage`
- Internet access can be needed during first boot because some instances install packages or download content

## How to deploy a lab with OpenTofu

The usual workflow is the same for each lab.

```bash
cd labs/Base-lab
tofu init
tofu plan
tofu apply
```

OpenTofu will create the Incus networks and instances described in the `.tf` files.

When you no longer need a lab, destroy it from the same folder:

```bash
tofu destroy
```

Recommended workflow:

1. move into the lab folder you want to deploy
2. run `tofu init` once to download the provider
3. run `tofu plan` to review what will be created
4. run `tofu apply` to deploy the lab
5. use Incus commands to interact with the instances

## How to use the labs with Incus

Once a lab is deployed, use the Incus CLI to inspect and access the instances.

Common commands:

```bash
incus list 
incus start <instance>
incus stop <instance>
incus shell <instance>
incus console <instances> --type=vga
```

If a lab uses an Incus project, check the current project first:

```bash
incus project list
incus project switch Windows-AD
```

## Available labs

### Base-lab

Folder: [`labs/Base-lab`](./Base-lab)

This is the base segmented environment used for general exercises. It creates:

- a WAN bridge and a LAN bridge
- a `Router-Firewall` instance between both networks
- `Attacker-external` on WAN
- `Attacker-internal` on LAN
- a `DVWA` target on LAN
- a generic `Target` container on LAN
- a `Windows` virtual machine on LAN

Main file:

- [`incus-setup-base.tf`](./Base-lab/incus-setup-base.tf)

Related documentation:

- [`isolation-to-host.md`](./Documentation/isolation-to-host.md)
- [`Reauthorize-traffic-LAN-WAN.md`](./Documentation/Reauthorize-traffic-LAN-WAN.md)

Additional setup note:

- the `Windows` VM in this lab is cloned from an existing Incus Windows template/snapshot (`windows-template` / `winclient-template`)

### Netflow-lab

Folder: [`labs/Netflow-lab`](./Netflow-lab)

This lab extends the base topology with NetFlow monitoring. It is useful for traffic generation, collection, and analysis exercises.

Main files:

- [`incus-setup-base-netflow.tf`](./Netflow-lab/incus-setup-base-netflow.tf)
- [`NETFLOW-GUIDE.md`](./Netflow-lab/NETFLOW-GUIDE.md)

Use this lab if you want to practice:

- generating traffic from the attacker hosts
- exporting flows from the router
- collecting flows on a NetFlow collector
- analyzing flows with `nfdump`

### Windows-AD-lab

Folder: [`labs/Windows-AD-lab`](./Windows-AD-lab)

This lab is focused on a Windows Active Directory environment and uses a dedicated Incus project named `Windows-AD`.

Main files:

- [`windows-AD.tf`](./Windows-AD-lab/windows-AD.tf)
- [`INFO.md`](./Windows-AD-lab/INFO.md)

Additional setup note:

- this lab depends on pre-installed Windows images/templates in Incus
- current VM definitions reference `windows-template` and `windows-server-template`
- current definitions also expect the `incus-storage` pool to exist
- follow [`Windows-installation.md`](./Documentation/Windows-installation.md) and the linked Incus forum guide before deploying it

After deployment, switch to the correct project if needed:

```bash
incus project switch Windows-AD
```

## Additional documentation

Shared documentation for multiple labs is stored in [`labs/Documentation`](./Documentation):

- [`isolation-to-host.md`](./Documentation/isolation-to-host.md): block access from lab networks to the host
- [`Reauthorize-traffic-LAN-WAN.md`](./Documentation/Reauthorize-traffic-LAN-WAN.md): re-open LAN/WAN forwarding rules when needed
- [`Windows-installation.md`](./Documentation/Windows-installation.md): Windows image/template preparation for Incus

## Create and submit your own lab

New labs are welcome.

To add your own lab:

1. create a new folder under `labs/`, for example `labs/My-New-Lab`
2. add the OpenTofu files needed to deploy it
3. add a short `README.md` that explains the goal of the lab, the instances it creates, and any special requirements
4. add extra documentation in the lab folder or in `labs/Documentation` if it is shared by several labs
5. test the lab with `tofu init`, `tofu plan`, and `tofu apply`
6. submit your changes through a pull request

Recommended contribution rules:

- keep names explicit and consistent
- document any required Incus project, image, snapshot, or storage pool
- document any manual post-deployment steps
- avoid committing generated local state or cache files unless they are intentionally part of the lab

If your lab is based on a specific use case, include enough documentation so someone else can deploy and use it without reverse-engineering the `.tf` files.
