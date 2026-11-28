"""Differential replay of defsToYaml (the default stringifier of the reference's YAML package) against its corpora: byte-identical text."""
import os

from atlas_pca.actions_yaml_emit import defs_to_yaml
from base_oracle import HERE, load, run


def _corpus(name):
    return load(name, os.path.join(HERE, "test-data", "ref-%s.json.gz" % name))[1]["defsToYaml"]


def test_plain_corpus():
    run(_corpus("core-yaml-java"), defs_to_yaml)


def _resolve(node, shared, built):
    if isinstance(node, dict):
        if set(node) == {"$ref"}:
            return built[node["$ref"]]
        return {k: _resolve(v, shared, built) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, shared, built) for v in node]
    return node


def _fill(node, built):
    """Replace {"$ref": id} in place so every reference is the ONE container built for that id."""
    if isinstance(node, dict):
        for k, v in list(node.items()):
            node[k] = built[v["$ref"]] if isinstance(v, dict) and set(v) == {"$ref"} else (_fill(v, built) or v)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            node[i] = built[v["$ref"]] if isinstance(v, dict) and set(v) == {"$ref"} else (_fill(v, built) or v)


def _anchors(ns, defs, rules, shared):
    built = {k: ([] if isinstance(v, list) else {}) for k, v in shared.items()}
    for k, v in shared.items():
        if isinstance(v, list):
            built[k].extend(v)
        else:
            built[k].update(v)
    for v in built.values():
        _fill(v, built)
    holder = [defs, rules]
    _fill(holder, built)
    return defs_to_yaml(ns, holder[0], holder[1])


def test_anchor_corpus():
    run(_corpus("core-yaml-anchors-java"), _anchors)
