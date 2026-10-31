"""Scoring harness against the organisers' ground-truth manifest.

Matches detections to the manifest's [line, byte, stream] entries and reports
the PRD metrics: detection, correct labels, attack path order, false alarms,
processing time, memory and incident open time.
"""
