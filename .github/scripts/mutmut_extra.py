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
