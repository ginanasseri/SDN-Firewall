# SDN-Firewall

## University Campus Network Simulation of a Software-Defined Network Firewall with Proxy ARP Optimization

**Author:** Gina Nasseri

Simulates a centralized SDN firewall for a campus network, enforcing different access rules for Admin and Student LANs, where Student LANs are isolated and Admin LANs have no restrictions, and which can be enabled/disabled by hosts in the Admin LAN. Network connectivity is optimized using Proxy ARP.  

The enable/disable feature is emulated by sending messages to specified TCP ports between admin hosts. 

See `SDN_firewall_paper.pdf` for a detailed write-up. 
---

## System Requirements

* Linux environment (Recommended for macOS: use Multipass to install an Ubuntu VM)
* [Mininet](http://mininet.org/) 

---

## Usage 

1. Add `uni_firewall.py` and `proxy_learning.py` into `/home/ubuntu/pox/ext` directory.
2. Launch network with `sudo python launch_network.py` (ensure `data_center.py` in working directory)
3. Start the controller in a second terminal  (recommended flags and formatting included): 
```
sudo ~/pox/pox.py log.level --DEBUG openflow.of_01 openflow.discovery host_tracker proxy_learning uni_firewall info.packet_dump samples.pretty_log
```
4. In Mininet CLI: 

   * Disable firewall: `mininet> h2 sh -c 'printf fw | nc 10.0.0.1 8888 -w 1'`
     
   * Re-enable firewall: `mininet> h1 sh -c 'printf fw | nc 10.0.0.2 9999 -w 1'`

   * Test connectivity: `pingall` (or ping hosts individually, see Mininet documentation for commands)

---

## Directory Contents

* `uni_firewall.py` – firewall and admin enable/disable logic 
* `proxy_learning.py` – learning algorithm with Proxy ARP
* `data_center.py` – custom 3-tier datacenter topology (depth=3, fanout=2)
* `launch_network.py` – starts Mininet and bootstraps connectivity
* `SDN_firewall_paper.pdf` – full project paper

