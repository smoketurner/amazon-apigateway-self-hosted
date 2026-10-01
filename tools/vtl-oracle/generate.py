#!/usr/bin/env python3
"""Generates oracle cases that are too repetitive to write by hand.

usage: generate.py operators-arithmetic
       generate.py operators-comparison
       generate.py whitespace
       generate.py random SEED COUNT

Each mode prints a JSON array with one case per line, in the format run.sh consumes. The output
depends only on the arguments, so committed files can be regenerated and diffed.
"""

import itertools
import json
import random
import sys

# ----- operators -----

OPERANDS = {
    "i1": "1", "i2": "2", "i0": "0", "im1": "-1", "i7": "7", "l3b": "3000000000", "imax": "2147483647",
    "d15": "1.5", "d2": "2.0", "d01": "0.1", "d0": "0.0",
    "sa": "'a'", "sb": "'b'", "s1": "'1'", "se": "''", "s15": "'1.5'",
    "bt": "true", "bf": "false", "nul": "$nothing", "l1": "[1]", "le": "[]", "m": "{}", "m1": "{'a':1}",
}


def operator_cases(group):
    """The operator matrix, split in two so each recorded file stays under 1 MB."""
    arithmetic = ["+", "-", "*", "/", "%"]
    comparison = ["==", "!=", "<", ">", "<=", ">=", "&&", "||"]
    cases = []
    for (an, a), (bn, b) in itertools.product(OPERANDS.items(), OPERANDS.items()):
        if group == "arithmetic":
            for op in arithmetic:
                cases.append({"name": f"arith.{an}.{bn}.{op}", "template": f"#set($r = {a} {op} {b})[$r]"})
        else:
            for op in comparison:
                template = f"#set($r = {a} {op} {b})[$r]#if({a} {op} {b})T#{{else}}F#{{end}}"
                cases.append({"name": f"cmp.{an}.{bn}.{op}", "template": template})
    if group == "arithmetic":
        for an, a in OPERANDS.items():
            cases.append({"name": f"unary.{an}.not", "template": f"#set($r = !{a})[$r]#if(!{a})T#{{else}}F#{{end}}"})
            cases.append({"name": f"unary.{an}.if", "template": f"#if({a})T#{{else}}F#{{end}}"})
            cases.append({"name": f"unary.{an}.out", "template": f"#set($r = {a})[$r]"})
    return cases


# ----- whitespace -----

def whitespace():
    prefixes = {
        "txt": "x", "ref": "$a", "refu": "$u", "refm": "$a.length()", "nl": "x\n", "none": "", "set": "#set($z = 1)",
        "brace": "${a}", "str": "'q'", "comment": "## c\n", "end": "#if(true)#end", "foreach": "#foreach($i in [1])#end",
    }
    gaps = {"s1": " ", "s2": "  ", "tab": "\t"}
    directives = {
        "set": "#set($b = 2)", "if": "#if(true)Y#end", "foreach": "#foreach($i in [7])Y#end", "else": "#if(false)N#else Y#end",
        "text": "T", "ref": "$a", "break": "#foreach($i in [7,8])$i#break#end",
    }
    cases = []
    for (pn, p), (gn, gap), (dn, d) in itertools.product(prefixes.items(), gaps.items(), directives.items()):
        cases.append({"name": f"gap.{pn}.{gn}.{dn}", "template": f"#set($a = 'A')[{p}{gap}{d}]"})
    closers = {
        "set": ("#set($b = 2)", ""), "if": ("#if(true)", "#end"), "ifend": ("#if(true)Y#end", ""),
        "else": ("#if(false)N#else", "#end"), "elseif": ("#if(false)N#elseif(true)", "#end"),
        "foreach": ("#foreach($i in [7])", "#end"), "foreachend": ("#foreach($i in [7])Y#end", ""),
        "comment": ("## c", ""), "block": ("#* c *#", ""), "ref": ("$a", ""),
        "fmtend": ("#if(true)Y#{end}", ""), "fmtelse": ("#if(false)N#{else}", "#end"),
    }
    suffixes = {
        "nl": "\n", "sp_nl": " \n", "tab_nl": "\t\n", "sp2_nl": "  \n", "crlf": "\r\n", "nl2": "\n\n", "sp": " ",
        "sp_x": " x", "nl_sp_x": "\n x", "sp_nl_x": " \nx", "cr": "\r",
    }
    for dn, (d, close) in closers.items():
        for sn, suffix in suffixes.items():
            cases.append({"name": f"tail.{dn}.{sn}", "template": f"#set($a = 'A')[{d}{suffix}Z{close}]"})
    return cases


# ----- random templates -----

PRELUDE = (
    "#set($s = 'Hello')#set($n = 5)#set($d = 2.5)#set($b = true)#set($l = [1, 2, 3])"
    "#set($m = {'a': 1, 'b': {'c': 2}})#set($e = '')#set($ls = ['x', 'y'])#set($nested = [[1, 2], [3]])#set($z = 0)\n"
)
REFS = [
    "$s", "$!s", "${s}", "$u", "$!u", "$!{u}", "$l", "$m", "$s.length()", "$l.size()", "$m.a", "$m.b.c", "$l[0]", "$l[-1]",
    "$l.get(1)", "$m.get('a')", "$m['b']", "$s.substring(1)", "$s.substring(1, 3)", "$s.toUpperCase()", "$n", "$d", "$b",
    "$u.x", "$s.nothing()", "$ls.get(0).length()", "$nested[0][1]", "$e", "$e.isEmpty()", "$l.isEmpty()", "$m.keySet()",
    "$m.values()", "$l.contains(2)", "$s.indexOf('l')", "$s.replace('l', 'L')", "$s.charAt(1)", "$z", "$nested.get(1).get(0)",
    "$m.size()", "$ls.size()", "$s.equals('Hello')", "$input.path('$.total')", "$input.json('$.items')", "$input.params('id')",
    "$util.urlEncode($s)", "$util.escapeJavaScript($s)", "$context.requestId", "$stageVariables.env",
    "$context.identity.sourceIp", "$util.base64Encode($s)", "$input.path('$.items')", "$input.path('$.items[0].name')",
    "$util.parseJson('[1,2]')", "$input.params()", "$input.json('$.name')",
]
LOOP_REFS = [
    "$foreach.index", "$foreach.count", "$foreach.hasNext", "$foreach.first", "$foreach.last", "$velocityCount", "$i", "$!i",
    "$foreach.parent.index",
]
TEXTS = [
    "abc", " ", "\n", "x y", "{\"k\": \"v\"}", ",", "[", "]", "(", ")", ".", "\t", "  ", "a\nb", ": ", "-", "100%", "$5", "\r\n",
    "end", "#5", "a#b", "'q'", "\"d\"", "\n  ", "  \n",
]
LITERALS = ["1", "2", "0", "-1", "7", "1.5", "2.0", "0.1", "'a'", "'b'", "''", "'1'", "true", "false", "3000000000"]
SOURCES = [
    "$input.path('$.items')", "$input.params().header", "$l", "$ls", "$m.keySet()", "[1..3]", "$nested", "[]", "$m.values()",
    "$u", "[3..1]", "[1, 2]", "$m.entrySet()",
]


class Generator:
    def __init__(self, seed):
        self.rng = random.Random(seed)

    def pick(self, items):
        return self.rng.choice(items)

    def operand(self, in_loop):
        if self.rng.random() < 0.4:
            return self.pick(LITERALS)
        refs = REFS + (LOOP_REFS if in_loop else [])
        return self.pick([r for r in refs if not r.startswith(("$!", "${"))])

    def expression(self, in_loop, depth=0):
        r = self.rng.random()
        if r < 0.45 or depth > 1:
            return self.operand(in_loop)
        if r < 0.7:
            return f"{self.operand(in_loop)} {self.pick(['+', '-', '*', '/', '%'])} {self.operand(in_loop)}"
        if r < 0.85:
            return f"{self.operand(in_loop)} {self.pick(['==', '!=', '<', '>', '<=', '>='])} {self.operand(in_loop)}"
        if r < 0.9:
            return f"({self.expression(in_loop, depth + 1)}) {self.pick(['+', '-', '*'])} {self.operand(in_loop)}"
        if r < 0.95:
            return self.pick(["[1, 2]", "{'k': 1}", "[1..3]", "[$n, 'x']", "{'k': $s}"])
        return f"{self.operand(in_loop)} {self.pick(['&&', '||'])} {self.operand(in_loop)}"

    def condition(self, in_loop):
        r = self.rng.random()
        if r < 0.3:
            return self.operand(in_loop)
        if r < 0.6:
            return f"{self.operand(in_loop)} {self.pick(['==', '!=', '<', '>', '<=', '>='])} {self.operand(in_loop)}"
        if r < 0.75:
            return f"!{self.operand(in_loop)}"
        if r < 0.9:
            return f"{self.operand(in_loop)} {self.pick(['&&', '||'])} {self.condition(in_loop)}"
        return self.pick(["true", "false", "$b", "$u", "$l.isEmpty()", "$m.containsKey('a')"])

    def gap(self):
        return self.pick(["", "", "\n", " \n", "  ", "\n  "])

    def block(self, depth, in_loop):
        return "".join(self.item(depth, in_loop) for _ in range(self.rng.randint(0, 4)))

    def item(self, depth, in_loop):
        r = self.rng.random()
        if r < 0.25:
            return self.pick(TEXTS)
        if r < 0.5:
            return self.pick(REFS + (LOOP_REFS if in_loop else []))
        if r < 0.62:
            if self.rng.random() < 0.1:
                return f"#set($context.requestOverride.header.h{self.rng.randint(1, 3)} = {self.expression(in_loop)}){self.gap()}"
            return f"#set(${self.pick(['v', 'w', 'n', 's', 'l'])} = {self.expression(in_loop)}){self.gap()}"
        if r < 0.66:
            return self.pick(["## comment\n", "#* c *#", "## c", "#* multi\nline *#\n"])
        if depth >= 3:
            return self.pick(TEXTS)
        if r < 0.82:
            out = f"#if({self.condition(in_loop)}){self.gap()}{self.block(depth + 1, in_loop)}"
            if self.rng.random() < 0.4:
                out += f"#elseif({self.condition(in_loop)}){self.gap()}{self.block(depth + 1, in_loop)}"
            if self.rng.random() < 0.5:
                out += f"#else{self.gap()}{self.block(depth + 1, in_loop)}"
            return out + f"#end{self.gap()}"
        if r < 0.95:
            body = self.block(depth + 1, True)
            if self.rng.random() < 0.2:
                body += self.pick(["#break", "#if($foreach.index == 1)#break#end", "#if($velocityCount > 1)#stop#end"])
            return f"#foreach($i in {self.pick(SOURCES)}){self.gap()}{body}#end{self.gap()}"
        return self.pick(["#break", "#stop", "\\$s", "\\#set($x = 1)", "\\\\$s"])


def random_templates(seed, count):
    generator = Generator(seed)
    return [
        {"name": f"random.{seed}.{index}", "template": PRELUDE + generator.block(0, False)}
        for index in range(count)
    ]


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    if mode in ("operators-arithmetic", "operators-comparison"):
        cases = operator_cases(mode.removeprefix("operators-"))
    elif mode == "whitespace":
        cases = whitespace()
    elif mode == "random" and len(argv) == 4:
        cases = random_templates(int(argv[2]), int(argv[3]))
    else:
        sys.exit(__doc__)
    lines = ",\n".join("  " + json.dumps(case, ensure_ascii=False) for case in cases)
    sys.stdout.write(f"[\n{lines}\n]\n")


if __name__ == "__main__":
    main(sys.argv)
