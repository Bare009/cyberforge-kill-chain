"""Incident builder (FR-4, B-3).

Groups detections that share an IP, user, host or domain within a time window
into incidents, caps hub entities so unrelated attacks do not merge, and counts
the raw alerts merged into each incident.
"""
