"""Attack paths and reach-next (FR-5, FR-6).

Orders each incident's steps in time and by kill chain stage, builds the
host/user graph with directed edges, and searches an access graph built from
logons, admin rights and connections for what the attacker could reach next.

chain.py           numbered chain, ongoing flags, gaps, chain_text (P7)
path.py            path graph nodes and edges (P7)
incident_files.py  provisional contract-C bundle files, checked then written atomically
cli.py             python -m killchain chain
"""

from .chain import build_chains, build_steps, chain_text, gaps, ongoing_flags, order_steps  # noqa: F401
from .path import node_for, path_graph  # noqa: F401
