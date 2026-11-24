"""Data-only expressions for the CTF extension, independently implemented.

This module does not import ToolchainMark's executor, receiver, or adapters.
It implements the declared expression vocabulary for a same-information oracle
comparison. It does not validate execution order or authenticate observations.
"""

from dataclasses import dataclass
import math
import re


class BaselineInputError(RuntimeError):
    """Malformed comparison input; never a scientific INESTIMABLE outcome."""


@dataclass(frozen=True)
class Evaluation:
    state: str
    value: object = None
    reason: str | None = None

    def to_dict(self):
        return {"state": self.state, "value": self.value, "reason": self.reason}


def same(left, right):
    """JSON equality with distinct bool, integer, and floating-point types."""
    if type(left) is not type(right):
        return False
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    if type(left) is dict:
        return left.keys() == right.keys() and all(same(left[k], right[k]) for k in left)
    return left == right


def _number(value):
    return type(value) in (int, float) and (type(value) is int or math.isfinite(value))


def _path(value, tokens, reason):
    for token in tokens:
        if type(token) is str and type(value) is dict and token in value:
            value = value[token]
        elif type(token) is int and type(value) is list and 0 <= token < len(value):
            value = value[token]
        else:
            return Evaluation("UNKNOWN", reason=reason)
    return Evaluation("VALUE", value)


def _operation(name, args):
    """Only called when every operand is a concrete JSON value."""
    failure = Evaluation("ERROR", reason=f"type-error:{name}")
    if name in ("eq", "ne"):
        answer = same(*args)
        return Evaluation("VALUE", answer if name == "eq" else not answer)
    if name in ("and", "or", "not"):
        if not all(type(arg) is bool for arg in args):
            return failure
        return Evaluation("VALUE", all(args) if name == "and" else any(args) if name == "or" else not args[0])
    if name in ("lt", "le"):
        left, right = args
        if not ((_number(left) and _number(right)) or (type(left) is str and type(right) is str)):
            return failure
        return Evaluation("VALUE", left < right if name == "lt" else left <= right)
    if name in ("contains", "in"):
        container, member = args if name == "contains" else args[::-1]
        if type(container) is list:
            return Evaluation("VALUE", any(same(item, member) for item in container))
        if type(container) is str and type(member) is str:
            return Evaluation("VALUE", member in container)
        return failure
    if name == "len":
        return Evaluation("VALUE", len(args[0])) if type(args[0]) in (str, list, dict) else failure
    if name in ("all_equal", "all_distinct"):
        values = args[0]
        if type(values) is not list:
            return failure
        if name == "all_equal":
            return Evaluation("VALUE", all(same(values[0], item) for item in values[1:]))
        return Evaluation("VALUE", all(not same(values[i], values[j]) for i in range(len(values)) for j in range(i)))
    if name == "concat":
        if all(type(arg) is str for arg in args):
            return Evaluation("VALUE", "".join(args))
        if all(type(arg) is list for arg in args):
            return Evaluation("VALUE", [item for arg in args for item in arg])
        return failure
    if name == "concat_hex":
        if all(type(arg) is str and re.fullmatch(r"(?:[0-9a-f]{2})*", arg) is not None for arg in args):
            return Evaluation("VALUE", "".join(args))
        return failure
    raise BaselineInputError(f"undeclared operation: {name}")


def evaluate(expression, inputs, actions, prior_verdicts):
    """Evaluate against raw observations and CTF's own earlier outcomes."""
    if type(expression) is not dict:
        raise BaselineInputError("expression must be an object")
    if set(expression) == {"literal"}:
        return Evaluation("VALUE", expression["literal"])
    for tag in ("input", "ref"):
        if tag in expression:
            if not set(expression) <= {tag, "path"} or type(expression[tag]) is not str:
                raise BaselineInputError(f"malformed {tag} expression")
            name = expression[tag]
            tokens = expression.get("path", [])
            if type(tokens) is not list or any(not (type(t) is str or type(t) is int and t >= 0) for t in tokens):
                raise BaselineInputError("invalid path tokens")
            if tag == "input":
                if name not in inputs:
                    raise BaselineInputError(f"undeclared input: {name}")
                return _path(inputs[name], tokens, f"input-path-missing:{name}")
            if name not in actions:
                raise BaselineInputError(f"missing planned observation: {name}")
            if actions[name]["status"] != "OK":
                return Evaluation("UNKNOWN", reason=f"action-unavailable:{name}")
            return _path(actions[name]["value"], tokens, f"action-path-missing:{name}")
    if set(expression) == {"available"}:
        name = expression["available"]
        if name not in actions:
            raise BaselineInputError(f"missing planned observation: {name}")
        return Evaluation("VALUE", actions[name]["status"] == "OK")
    if set(expression) == {"verdict"}:
        name = expression["verdict"]
        if name not in prior_verdicts:
            raise BaselineInputError(f"missing prior CTF judgment: {name}")
        return Evaluation("VALUE", prior_verdicts[name])
    if set(expression) != {"op", "args"} or type(expression["args"]) is not list:
        raise BaselineInputError("malformed operation expression")
    name, expressions = expression["op"], expression["args"]
    arities = {"eq": 2, "ne": 2, "contains": 2, "in": 2, "lt": 2, "le": 2,
               "not": 1, "len": 1, "all_equal": 1, "all_distinct": 1}
    if name in arities:
        if len(expressions) != arities[name]:
            raise BaselineInputError(f"wrong arity: {name}")
    elif name not in ("and", "or", "concat", "concat_hex") or not expressions:
        raise BaselineInputError(f"unknown operation or empty operands: {name}")
    children = [evaluate(arg, inputs, actions, prior_verdicts) for arg in expressions]
    for state in ("ERROR", "UNKNOWN"):
        for child in children:
            if child.state == state:
                return child
    return _operation(name, [child.value for child in children])


def boolean(expression, inputs, actions, prior_verdicts):
    result = evaluate(expression, inputs, actions, prior_verdicts)
    if result.state != "VALUE":
        return result
    if type(result.value) is not bool:
        return Evaluation("ERROR", reason="boolean-required")
    return Evaluation("TRUE" if result.value else "FALSE", result.value)
