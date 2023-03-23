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

    def poss_t_def(self, cfg, json):
        self.cfg = cfg
        self.nodeset = self.cfg.get_nodes()


if __name__ == "__main__":

    cfgreader = CFGReader()
    astreader = ASTReader()
    t_analyzer = TAnalyzer()
    t_analyzer.load_json("../tp/part_1/file_1.php.taint.json")
