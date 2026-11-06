# Vendored from MHBench (github.com/bsinger98/MHBench), MIT © 2025 Brian Singer.
# Env schema + topology generator, adapted only by rewriting src.*->mhbench.* imports.
# License: third_party/mhbench/LICENSE. See swarm/mhbench_schema.py for the duelswarm shim.
"""MHBench NetworkTopology IR + topology generator, vendored for duelswarm (M0).

Substrate-agnostic parts only: models/ (the schema) and topology_generator/ (pure
Python, no OpenStack). The OpenStack/Terraform/Ansible deployers were NOT vendored.
"""
