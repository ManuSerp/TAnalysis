from code_analysis import *
import json


class TAnalyzer:
    def __init__(self):
        self.cfg = None
        self.ast = None
        self.json = None

    def load_json(self, json_path):
        with open(json_path) as json_file:
            self.json = json.load(json_file)
        print(self.json)

    def gen_def(self, node):
        if node in self.json["sources"]:
            return set({node})
        else:
            parent = self.ast.get_parents(node)[0]
            if self.cfg.get_type(parent) == "BinOP":
                arg = self.cfg.get_var_op(parent)
                def_tainted = []
                for a in arg:
                    for p in self.json["pairs"]:
                        if a == p[1]:
                            defi = p[0]
                            if defi in OUT[node-self.index]:
                                def_tainted.add(defi)
                return set(def_tainted)
            else:
                return set()

    def kill_def(self, node):
        res = []
        if node in self.json["defs"]:
            name = self.cfg.get_image(node)
            for d in self.json["defs"]:
                if self.cfg.get_image(d) == name:
                    res.append(d)
        return set(res)

    def get_var_op(self, node):
        res = []
        if self.cfg.get_type(node) == "BinOP":
            hands = self.cfg.get_op_hands(node)
            if self.cfg.get_type(hands[0]) == "Variable":
                res.append(hands[0])
            elif self.cfg.get_type(hands[0]) == "BinOP":
                res.extend(self.get_var_op(hands[0]))
            elif self.cfg.get_type(hands[1]) == "Variable":
                res.append(hands[1])
            elif self.cfg.get_type(hands[1]) == "BinOP":
                res.extend(self.get_var_op(hands[1]))
        return res

    def poss_t_def(self, cfg: CFG, json):
        self.cfg = cfg
        self.nodeset = self.cfg.get_nodes()
        self.index = self.cfg.get_root()
        IN = [set() for i in range(len(self.nodeset))]
        OUT = [set() for i in range(len(self.nodeset))]
        old_out = [set() for i in range(len(self.nodeset))]

        changes = True
        while changes:
            changes = False
            for node in self.nodeset:
                nodeindex = node-self.index
                uni = set()
                for pred in self.cfg.get_parents(node):
                    predindex = pred-self.index
                    uni = uni.union(OUT[predindex])
                    IN[nodeindex] = uni
                    old_out[nodeindex] = OUT[nodeindex]
                    OUT[nodeindex] = self.gen_def(nodeindex).union(
                        IN[nodeindex] - self.kill_def(nodeindex))
                    if OUT[nodeindex] != old_out[nodeindex]:
                        changes = True
        return OUT


if __name__ == "__main__":

    cfgreader = CFGReader()
    astreader = ASTReader()
    t_analyzer = TAnalyzer()
    t_analyzer.load_json("../tp/part_1/file_1.php.taint.json")
