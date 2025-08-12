class Calculator:
    def transform_expr(self, expr: str) -> str:
        # SOURCE: `expr` is user-controlled
        # PROPAGATOR: passed through unchanged (minor transform allowed)
        return expr.strip()

    def eval_expr(self, expr: str):
        to_eval = self.transform_expr(expr)  # PROPAGATOR
        return eval(to_eval)  # SINK: dynamic code execution

def compute(expr: str):
    # SOURCE: `expr` comes from user input
    calc = Calculator()
    return calc.eval_expr(expr)  # SINK via eval
