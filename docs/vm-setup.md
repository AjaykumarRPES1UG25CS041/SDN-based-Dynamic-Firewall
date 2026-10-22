# VM Setup (VirtualBox, SSH, VS Code)

How to get an Ubuntu 22.04 VM on a Windows computer and connect to it from
Windows. After this, continue with "Setup on a fresh Ubuntu 22.04 VM" in the
[README](../README.md) to install Mininet, Open vSwitch and OS-Ken.

The project needs Linux because Mininet and Open vSwitch run only there.
Everything is run inside the VM; Windows is only used to edit files and open
terminals.

## 1. Create the VM in VirtualBox

1. Create a new VM named `CN-Project-Ubuntu`.
2. Use an official **Ubuntu 22.04.5 LTS Desktop** ISO.
3. Tick **Skip Unattended Installation** in the VM creation dialog, so the
   normal Ubuntu installer runs and you choose your own username and
   password.
4. Memory: **4 GB RAM**. Disk: **25 GB** virtual disk. CPUs: the development VM
   used 4.
5. Network: keep the default adapter in **NAT** mode.
6. Start the VM and finish the Ubuntu installation.

## 2. Enable SSH inside Ubuntu

SSH lets you work from Windows instead of the VM window. In an Ubuntu terminal:

```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
systemctl status ssh
```

The service should show as `active (running)`.

## 3. Forward a port from Windows to the VM

In VirtualBox open the VM's **Settings, Network, Adapter 1, Advanced, Port
Forwarding** and add one rule:

| Field      | Value       |
|------------|-------------|
| Name       | `SSH`       |
| Protocol   | `TCP`       |
| Host IP    | `127.0.0.1` |
| Host Port  | `2222`      |
| Guest IP   | (leave blank) |
| Guest Port | `22`        |

This maps `127.0.0.1:2222` on Windows to port 22 in the VM, so the VM is
reachable only from your own computer.

## 4. Connect from Windows

In PowerShell (the VM must be running):

```powershell
ssh -p 2222 <ubuntu-username>@127.0.0.1
```

Replace `<ubuntu-username>` with the username you created in Ubuntu. The first
time, confirm the host key (it is your own VM) and enter your Ubuntu password.

### Optional: VS Code Remote - SSH

1. Install Visual Studio Code and the **Remote - SSH** extension.
2. Press `Ctrl+Shift+P`, choose **Remote-SSH: Connect to Host...** and enter
   `ssh -p 2222 <ubuntu-username>@127.0.0.1`.
3. Open the project folder in the VM, for example
   `/home/<ubuntu-username>/sdn-dynamic-firewall`.
4. Use a terminal in that VS Code window to run the Linux commands.

If the connection fails, check that the VM is running, that `ssh` is active
(step 2) and that the port forwarding rule exists (step 3).

## 5. Next

Install the packages, clone the repository and create the OS-Ken virtual
environment as described in the [README](../README.md).
