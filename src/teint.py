from code_analysis import *


class TAnalyzer:
    def __init__(self):
        self.cfg = None
        self.ast = None


if __name__ == "__main__":

    cfgreader = CFGReader()
    astreader = ASTReader()
