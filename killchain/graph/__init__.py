"""Attack paths and reach-next (FR-5, FR-6).

Orders each incident's steps in time and by kill chain stage, builds the
host/user graph with directed edges, and searches an access graph built from
logons, admin rights and connections for what the attacker could reach next.
"""
