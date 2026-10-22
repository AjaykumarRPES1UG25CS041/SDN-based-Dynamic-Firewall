#!/usr/bin/env python3
"""Make the result charts from results/results.csv (needs matplotlib).

    python experiments/plot_results.py [--csv results/results.csv]

Saves two PNG files next to the CSV:
  results_h1_under_attack.png   h1 RTT and throughput while h4 attacks
  results_attack_and_block.png  attack connections that got through, and
                                the time the controller needed to block
Rows with the same label and delay (repeated runs) are averaged.
"""
import argparse
import csv
import os

import matplotlib
matplotlib.use("Agg")   # draw to files only, no window needed
import matplotlib.pyplot as plt

LABELS = ["no_firewall", "static", "dynamic"]
NAMES = {"no_firewall": "No firewall", "static": "Static policy",
         "dynamic": "Dynamic firewall"}
COLORS = {"no_firewall": "#0072B2", "static": "#E69F00", "dynamic": "#009E73"}


def read_rows(path):
    """Return {(label, delay): {column: mean value or None}}."""
    groups = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            groups.setdefault((row["label"], row["delay"]), []).append(row)
    table = {}
    for key, rows in groups.items():
        table[key] = {}
        for col in rows[0]:
            if col in ("label", "delay"):
                continue
            vals = [float(r[col]) for r in rows if r[col] != ""]
            table[key][col] = sum(vals) / len(vals) if vals else None
    return table


def delay_value(text):
    digits = "".join(c for c in text if c.isdigit() or c == ".")
    return float(digits) if digits else 0.0


def grouped_bars(ax, table, delays, column, ylabel, title, decimals=1,
                 log=False):
    """One group per delay, one bar per setup."""
    width = 0.25
    for i, label in enumerate(LABELS):
        xs, ys = [], []
        for j, delay in enumerate(delays):
            xs.append(j + (i - 1) * width)
            ys.append(table.get((label, delay), {}).get(column))
        heights = [y if y is not None else 0 for y in ys]
        bars = ax.bar(xs, heights, width, label=NAMES[label],
                      color=COLORS[label])
        for bar, y in zip(bars, ys):
            text = "n/a" if y is None else ("%.*f" % (decimals, y))
            ax.annotate(text, (bar.get_x() + bar.get_width() / 2,
                               bar.get_height()), ha="center", va="bottom",
                        fontsize=8, xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(range(len(delays)))
    ax.set_xticklabels(delays)
    ax.set_xlabel("Link delay (per interface)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if log:
        ax.set_yscale("log")   # values differ by orders of magnitude
    ax.margins(y=0.15)
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)


def add_legend(fig, ax):
    """One legend below the charts so it never covers a bar."""
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels))
    fig.tight_layout(rect=[0, 0.07, 1, 1])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_csv = os.path.join(os.path.dirname(here), "results", "results.csv")
    p = argparse.ArgumentParser(description="Plot experiment results")
    p.add_argument("--csv", default=default_csv)
    args = p.parse_args()

    table = read_rows(args.csv)
    delays = sorted({d for _, d in table}, key=delay_value)
    out_dir = os.path.dirname(os.path.abspath(args.csv))

    # Chart 1: what h1 sees while the attack is running
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    grouped_bars(ax1, table, delays, "attack_rtt_ms", "Average RTT (ms)",
                 "h1 round-trip time during the attack", 2)
    grouped_bars(ax2, table, delays, "attack_mbps", "Throughput (Mbit/s)",
                 "h1 throughput to h5 during the attack (iperf, log scale)",
                 0, log=True)
    add_legend(fig, ax1)
    path1 = os.path.join(out_dir, "results_h1_under_attack.png")
    fig.savefig(path1, dpi=150)

    # Chart 2: attack success and reaction time
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    grouped_bars(ax1, table, delays, "attack_conns_succeeded",
                 "Connections that succeeded",
                 "Attack connections that got through", 0)
    grouped_bars(ax2, table, delays, "block_response_ms",
                 "Time to block (ms)",
                 "Blocking response time (n/a = never blocked)")
    add_legend(fig, ax1)
    path2 = os.path.join(out_dir, "results_attack_and_block.png")
    fig.savefig(path2, dpi=150)

    print("saved", path1)
    print("saved", path2)


if __name__ == "__main__":
    main()
