"""Supplemental mutants for mutmut 3.8.1, covering only what its own operators never produce. install() before create_mutants.

mutmut alters operators, literals, arguments and assigned values, but it never deletes a statement, never mutates inside
isinstance()/len(), and skips every decorated function except @staticmethod/@classmethod. That left guards like
`if e: return e`, `if not isinstance(x, dict): raise ...`, bare check calls, continue/break and whole methods unmutated. Added:
  - decorated functions are mutated like any other; the trampoline keeps the decorators and the original and mutant copies
    drop them (a @property or a locking wrapper must run once, around the trampoline, not again around each copy)
  - an `if`/`elif` test with no mutmut mutant inside it is forced to False (the guard is removed)
  - each `raise`, each expression-statement call, each `continue` and `break` is replaced by `pass`
  - a function that still has no mutant gets its returns replaced (`return x` -> `return None`, `return None` -> `return True`)
mutmut-site-check.py verifies afterwards that every such site got at least one mutant."""
import ast
import dataclasses

import libcst as cst

NEVER_INSIDE = {"len", "isinstance"}  # mutmut never mutates inside these calls (file_mutation.NEVER_MUTATE_FUNCTION_CALLS)
KEEP_ON_COPIES = {"staticmethod", "classmethod"}  # mutmut's own trampoline needs these on the copies


def has_mutmut_mutant(node, operators):
    """Would one of mutmut's own operators mutate something in `node`? (mutmut skips len()/isinstance() calls)"""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, cst.Call) and isinstance(n.func, cst.Name) and n.func.value in NEVER_INSIDE:
            continue
        for t, op in operators:
            if isinstance(n, t) and next(iter(op(n)), None) is not None:
                return True
        stack.extend(n.children)
    return False


def install():
    from mutmut.mutation import file_mutation as fm
    from mutmut.mutation import mutators as mm

    own = list(mm.mutation_operators)  # mutmut's operators, before ours are added

    def force_false(node):
        if not has_mutmut_mutant(node.test, own):
            yield node.with_changes(test=cst.Name("False"))

    def remove(node):
        yield cst.Pass()

    def remove_call(node):
        if isinstance(node.value, cst.Call):
            yield cst.Pass()

    mm.mutation_operators.extend([(cst.If, force_false), (cst.Raise, remove), (cst.Expr, remove_call),
                                  (cst.Continue, remove), (cst.Break, remove)])  # fm imported the same list object
    assert fm.mutation_operators is mm.mutation_operators

    skip = fm.MutationVisitor._skip_node_and_children

    def skip_node(self, node):
        if isinstance(node, cst.FunctionDef) and node.decorators:
            pos = self.get_metadata(fm.PositionProvider, node, None)
            if (pos and pos.start.line in self._ignored_node_lines) or node in self._enum_creation_hooks \
                    or node.name.value in fm.NEVER_MUTATE_FUNCTION_NAMES:
                return skip(self, node)
            return False  # its decorator nodes stay unmutated (mutmut skips cst.Decorator)
        return skip(self, node)

    fm.MutationVisitor._skip_node_and_children = skip_node

    arrange = fm.function_trampoline_arrangement

    def arrangement(function, mutants, class_name):
        decls, nodes, assigns, names = arrange(function, mutants, class_name)
        if len(names) >= BIG_FUNCTION:
            print(f"  building {len(names)} mutants of {class_name + '.' if class_name else ''}{function.name.value}", flush=True)

        def bare(f):
            return f.with_changes(decorators=[d for d in f.decorators
                                              if isinstance(d.decorator, cst.Name) and d.decorator.value in KEEP_ON_COPIES])

        return decls, [nodes[0]] + [bare(f) for f in nodes[1:]], assigns, names

    fm.function_trampoline_arrangement = arrangement

    create = fm.create_mutations

    def create_mutations(filename, code, covered_lines=None, coverage_excluded_lines=None):
        module, mutations, ignored_classes, ignored_functions = create(filename, code, covered_lines, coverage_excluded_lines)
        mutated = {m.contained_by_top_level_function for m in mutations}
        funcs = [n for n in module.body if isinstance(n, cst.FunctionDef)]
        funcs += [f for c in module.body if isinstance(c, cst.ClassDef) and isinstance(c.body, cst.IndentedBlock)
                  for f in c.body.body if isinstance(f, cst.FunctionDef)]
        for f in funcs:
            if f in mutated or f.name.value in fm.NEVER_MUTATE_FUNCTION_NAMES or f.name.value in ignored_functions:
                continue
            for r in _returns(f):  # a function nothing else mutates: its result is replaced
                none = r.value is None or (isinstance(r.value, cst.Name) and r.value.value == "None")
                mutations.append(fm.Mutation(original_node=r, mutated_node=r.with_changes(value=cst.Name("True" if none else "None")),
                                             contained_by_top_level_function=f))
        return module, mutations, ignored_classes, ignored_functions

    fm.create_mutations = create_mutations
    fm.deep_replace = shared_replace  # function_trampoline_arrangement looks it up as a module global
    fm.render_and_collect_line_spans = render_and_collect_line_spans  # combine_mutations_to_source looks it up as a module global
    import mutmut.__main__ as main
    main.ast = _ChunkedAst()  # create_mutants_for_file's syntax check of the written file: `ast.parse(f.read())`


def shared_replace(tree, old_node, new_node):
    """mutmut's deep_replace (one occurrence of old_node, by identity) rebuilding only the path from `tree` down to it.

    mutmut's own runs a libcst transformer, which re-creates every node it visits: about half of the function per mutant, and
    every copy stays alive until the file is rendered. evidence_verify._replay (~2,500 mutants of a 690-line function) took the
    one generation worker past the 16 GB runner. Here every other subtree is shared with the original (libcst nodes are
    immutable), so the rendered code is the same and a file's mutants cost their changed paths only."""
    if tree is old_node:
        return new_node
    for f in dataclasses.fields(tree):
        v = getattr(tree, f.name)
        if isinstance(v, cst.CSTNode):
            r = shared_replace(v, old_node, new_node)
            if r is not v:
                return tree.with_changes(**{f.name: r})
        elif isinstance(v, (tuple, list)):
            for i, x in enumerate(v):
                if isinstance(x, cst.CSTNode):
                    r = shared_replace(x, old_node, new_node)
                    if r is not x:
                        return tree.with_changes(**{f.name: type(v)([*v[:i], r, *v[i + 1:]])})
    return tree


BIG_FUNCTION = 500  # mutants of one function from which generation prints its phases
CHUNK_LINES = 20000  # a class rendered longer than this is syntax-checked one member at a time
_layout = {}  # the file this worker rendered last: its length, line count and parse units (process-local, one file at a time)


def render_and_collect_line_spans(module):
    """mutmut 3.8.1's render_and_collect_line_spans, same code, also recording the line range of each top-level statement.

    mutmut then re-reads the written file and checks it with one ast.parse: for evidence_verify.py (~2,500 copies of a 690-line
    function, ~180 MB of source) the Python AST of the whole file took the generation worker past the 16 GB runner after the
    mutants were built and written. The ranges let _ChunkedAst check the same text one top-level statement at a time."""
    from mutmut.mutation import file_mutation as fm
    parts = [module.code_for_node(empty_line) for empty_line in module.header]
    line_spans = {}
    line = 1 + sum(part.count("\n") for part in parts)
    units = [(0, line - 1, 0, 0)] if line > 1 else []  # (first line, end line, and the header lines parsed before them)
    for statement in module.body:
        part = module.code_for_node(statement)
        fm.collect_line_spans(module, statement, part, start_line=line, line_spans=line_spans)
        parts.append(part)
        n = part.count("\n")
        units += _class_units(module, statement, part, line - 1) if n > CHUNK_LINES else [(line - 1, line - 1 + n, 0, 0)]
        line += n
    footer = [module.code_for_node(empty_line) for empty_line in module.footer]
    parts.extend(footer)
    if footer:
        units.append((line - 1, line - 1 + sum(p.count("\n") for p in footer), 0, 0))
    code = "".join(parts)
    if not module.has_trailing_newline:
        code = code.removesuffix(module.default_newline)
    if len(code) > 10_000_000:
        print(f"  rendered {len(code) // 1_000_000} MB in {len(units)} parse units", flush=True)
    _layout.clear()
    _layout.update(length=len(code), units=units)
    return code, line_spans


def _class_units(module, statement, part, start):
    """A long class as units of (its header lines + one member); its header line count is the one collect_line_spans computes."""
    n = part.count("\n")
    whole = [(start, start + n, start, start)]
    if not isinstance(statement, cst.ClassDef) or not isinstance(statement.body, cst.IndentedBlock) or len(statement.body.body) < 2:
        return whole
    counts = [module.code_for_node(child).count("\n") for child in statement.body.body]
    header = n - sum(counts) - len(statement.body.footer)
    if header < 1:
        return whole
    counts[-1] += len(statement.body.footer)
    units, line = [], start + header
    for c in counts:
        units.append((line, line + c, start, start + header))
        line += c
    units[0] = (start, units[0][1], start, start)  # the first member's unit is the header plus the member, as written
    return units


class _ChunkedAst:
    """`ast` for mutmut.__main__: parse() of the file this worker just rendered parses each recorded unit (lines s:e, preceded by
    lines hs:he: the class header of a member) on its own; text that does not match the recorded layout (another file) gets the
    whole-file ast.parse. A SyntaxError carries its line number in the whole file."""

    def __getattr__(self, name):
        return getattr(ast, name)

    def parse(self, source, *args, **kwargs):
        units = _layout.get("units")
        if args or kwargs or not units or len(source) != _layout["length"]:
            return ast.parse(source, *args, **kwargs)
        lines = source.split("\n")  # mutmut wrote and re-read the file in text mode: "\n" is the only line end left
        total = len(lines) - 1 if source.endswith("\n") else len(lines)
        if units[0][0] != 0 or units[-1][1] != total or any(u[1] != v[0] for u, v in zip(units, units[1:])):
            print(f"  syntax check: the recorded layout does not cover this file: whole-file ast.parse ({len(source)} chars)", flush=True)
            return ast.parse(source, *args, **kwargs)
        if len(source) > 10_000_000:
            print(f"  syntax check: {len(units)} parse units", flush=True)
        for s, e, hs, he in units:
            try:
                ast.parse("".join(line + "\n" for line in lines[hs:he] + lines[s:e]))
            except SyntaxError as err:
                if err.lineno is not None:
                    err.lineno = hs + err.lineno if err.lineno <= he - hs else s + err.lineno - (he - hs)
                raise
        return None  # mutmut discards the tree


def _returns(node):
    """The return statements of a function, not of the functions nested in it."""
    out, stack = [], list(node.body.children)
    while stack:
        n = stack.pop()
        if isinstance(n, cst.Return):
            out.append(n)
        elif not isinstance(n, (cst.FunctionDef, cst.Lambda)):
            stack.extend(n.children)
    return out
