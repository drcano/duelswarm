# Frozen scoring snapshot — old pre-seq-52 descriptor (entry,breadth,stealth,depth)

Verbatim copy of swarm/{population,arms_race,degeneracy,novelty}.py at commit `2260f7b`,
the descriptor era this run was SCORED under, with intra-swarm imports rewritten to flat so
the package imports with only this directory on sys.path (no `swarm/` needed). This is what
makes the sibling prove script a FROZEN audit: a later engine change to the live descriptor
cannot silently rewrite what this run's proof re-derives (audit I8). Pinned by MANIFEST.sha256,
which the prove script asserts before use.
