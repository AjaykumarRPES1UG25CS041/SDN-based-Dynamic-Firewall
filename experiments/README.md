# Experiments

Measures how a connection flood from h4 affects a normal client (h1), for
three setups and two link delays. The method and metrics are described in
`docs/architecture.md`, section "Performance Evaluation".

Each run appends one row to `results/results.csv`.

## Requirements (VM)

- Mininet, Open vSwitch and OS-Ken as for the other tests
- `iperf` (`sudo apt install iperf`)

## Running

Six runs: three setups, each at two delays. For each setup, start its
controller in Terminal 1, then run both delays in Terminal 2. Stop the
controller (Ctrl+C) before switching to the next setup.

Terminal 1 starts the controller for the setup:

| Label         | Terminal 1 command |
|---------------|--------------------|
| `no_firewall` | `osken-manager controller/learning_switch.py` |
| `static`      | `FW_DYNAMIC=0 osken-manager controller/firewall.py` |
| `dynamic`     | `osken-manager controller/firewall.py` |

(In Terminal 1 first run `source /home/vboxuser/osken/venv/bin/activate` and
`cd ~/sdn-dynamic-firewall`.)

Terminal 2, for the same label (replace `<label>`):

```bash
cd ~/sdn-dynamic-firewall
sudo mn -c
sudo python3 experiments/run_experiment.py --label <label> --delay 0ms
sudo mn -c
sudo python3 experiments/run_experiment.py --label <label> --delay 20ms
```

Options: `--attack-count` (default 300) and `--attack-timeout` (connect timeout
of the attacker in seconds, default 0.3).

A run with the dynamic firewall can take a minute or more, because the blocked
attacker keeps trying until its 300 attempts are used up (each failed attempt
waits for the attack timeout).

## Plots (Windows)

```
pip install matplotlib
python experiments/plot_results.py
```

This reads `results/results.csv` and writes
`results/results_h1_under_attack.png` and
`results/results_attack_and_block.png`. Repeated runs with the same label and
delay are averaged.
