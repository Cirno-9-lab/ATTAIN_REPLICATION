# %%
import networkx as nx
from tree_sitter import Language, Parser
import tree_sitter as ts
import matplotlib.pyplot as plt
import copy


# %%
class Basic_block:
    def __init__(self, id) -> None:
        self.id = id
        self.cfg_nodes_ids = []
        self.cfg_nodes = []
        self.pred_blocks_ids = []
        self.succ_blocks_ids = []
        self.is_break = False
        self.is_continue = False
        self.is_goto = False
        self.is_ret = False

        self.is_begBlock = False
        self.is_endBlock = False

    def add_pred_id(self, pred_id):
        self.pred_blocks_ids.append(pred_id)

    def add_succ_id(self, succ_id):
        self.succ_blocks_ids.append(succ_id)

    def get_preds_ids(self):
        return self.pred_blocks_ids

    def get_succs_ids(self):
        return self.succ_blocks_ids

    def add_cfg_nodes_ids(self, node_id):
        self.cfg_nodes_ids.append(node_id)

    def get_cfg_nodes_ids(self):
        return self.cfg_nodes_ids

    def add_cfg_nodes(self, node):
        self.cfg_nodes.append(node)

    def get_cfg_nodes(self):
        return self.cfg_nodes

    def set_break(self, b):
        self.is_break = b

    def get_break(self):
        return self.is_break

    def set_return(self, b):
        self.is_ret = b

    def get_return(self):
        return self.is_ret

    def set_continue(self, b):
        self.is_continue = b

    def get_continue(self):
        return self.is_continue

    def set_goto(self, b):
        self.is_goto = b

    def get_goto(self):
        return self.is_goto

    def link_to_follow_block(self):
        return (
            (not self.get_break())
            and (not self.get_continue())
            and (not self.get_goto())
        )

    def set_goto_node(self, node):
        self.goto_node = node

    def get_goto_node(self):
        return self.goto_node

    def set_labelstmt_node(self, node):
        self.labelstmt_node = node

    def get_labelstmt_node(self):
        return self.labelstmt_node

    def get_isbeg(self):
        return self.is_begBlock

    def set_isbeg(self, b):
        self.is_begBlock = b

    def get_isend(self):
        return self.is_endBlock

    def set_isend(self, b):
        self.is_endBlock = b

    def get_beg_line(self):
        if self.get_isbeg():
            return 0
        if self.get_isend():
            return 99999
        if len(self.cfg_nodes) == 0:
            return -1
        beg_line = self.cfg_nodes[0].start_point[0]
        return beg_line + 1

    def get_end_line(self):
        if self.get_isbeg():
            return 0
        if self.get_isend():
            return 99999
        if len(self.cfg_nodes) == 0:
            return -1

        if self.cfg_nodes[-1].type == "case_statement":
            return self.cfg_nodes[-1].start_point[0] + 1

        end_line = self.cfg_nodes[-1].end_point[0]
        return end_line + 1

    def is_blank_block(self):
        return (
            (not self.get_isbeg())
            and (not self.get_isend())
            and (len(self.cfg_nodes) == 0)
        )


# %%
class CFG:
    def __init__(self, func_node) -> None:
        self.cfg = nx.DiGraph()
        self.preds = []
        self.break_preds = []
        self.continue_preds = []
        self.gotos = {}
        self.goto_label_id_map = {}
        self.labels = {}
        self.id = 0
        self.basic_block_id = 0
        self.basic_blocks = {}
        self.continue_basic_blocks = []
        self.break_basic_blocks = []
        self.current_basic_block = None

        self.labeled_basic_blocks = []
        self.goto_basic_blocks = []
        self.beg_basic_block = None
        self.end_basic_block = None
        self.visit(func_node)

    def visit(self, n: ts.Node):
        getattr(self, "visit_" + n.type, self.visit_default)(n)

    def visit_function_definition(self, n: ts.Node):
        func_def_node = n
        func_def_child_cnt = func_def_node.child_count
        func_decl_text = ""
        ast_nodes = []
        for i in range(0, func_def_child_cnt - 1):
            func_def_child = func_def_node.child(i)
            ast_nodes.append(func_def_child)
            func_decl_text = func_decl_text + func_def_child.text.decode() + " "

        func_decl_id = self.get_node_id()
        self.cfg.add_node(
            func_decl_id,
            ast_nodes=ast_nodes,
            text=func_decl_text.strip(),
            is_cond=False,
        )
        self.preds.append([func_decl_id, "Uncond"])

        self.beg_basic_block = self.new_basic_block()
        self.beg_basic_block.set_isbeg(True)

        self.current_basic_block = self.new_basic_block()
        self.current_basic_block.add_cfg_nodes_ids(func_decl_id)
        for node in ast_nodes:
            self.current_basic_block.add_cfg_nodes(node)

        self.visit(func_def_node.child(func_def_child_cnt - 1))

        self.end_basic_block = self.new_basic_block()
        self.end_basic_block.set_isend(True)
        # to do
        # handle go to statements and get rid of redundant nodes

        # print(f'current goto_node length:{len(self.gotos)}')
        for goto_str, goto_node_ids in self.gotos.items():
            if goto_str in self.labels:
                label_id = self.labels[goto_str]
                for goto_node_id in goto_node_ids:
                    self.cfg.add_edge(goto_node_id, label_id, condition="Uncond")
                    # print(f'add goto_node_id:{goto_node_id} to self.goto_label_id_map')
                    self.goto_label_id_map[goto_node_id] = label_id

        for goto_basic_block in self.goto_basic_blocks:
            for succ_id in goto_basic_block.get_succs_ids():
                succ_basic_block = self.get_basic_block(succ_id)
                pred_ids = succ_basic_block.get_preds_ids()
                if goto_basic_block.id in pred_ids:
                    pred_ids.remove(goto_basic_block.id)

            goto_basic_block.get_succs_ids().clear()

            goto_node_id = goto_basic_block.get_goto_node()
            for labeled_basic_block in self.labeled_basic_blocks:
                label_node_id = labeled_basic_block.get_labelstmt_node()
                if self.goto_label_id_map[goto_node_id] == label_node_id:
                    goto_basic_block.add_succ_id(labeled_basic_block.id)
                    labeled_basic_block.add_pred_id(goto_basic_block.id)

        # deal return basic block
        for id, basic_block in self.basic_blocks.items():
            if basic_block.get_return():
                for succ_id in basic_block.get_succs_ids():
                    succ_basic_block = self.get_basic_block(succ_id)
                    succ_basic_block.get_preds_ids().remove(id)
                basic_block.get_succs_ids().clear()

        for id, basic_block in self.basic_blocks.items():
            if (
                len(basic_block.get_preds_ids()) == 0
                and basic_block != self.beg_basic_block
                and basic_block != self.end_basic_block
            ):
                basic_block.add_pred_id(self.beg_basic_block.id)
                self.beg_basic_block.add_succ_id(id)
            if (
                len(basic_block.get_succs_ids()) == 0
                and basic_block != self.end_basic_block
                and basic_block != self.beg_basic_block
            ):
                basic_block.add_succ_id(self.end_basic_block.id)
                self.end_basic_block.add_pred_id(id)

    def visit_declaration(self, n: ts.Node):
        decl_node_id = self.get_node_id()
        self.cfg.add_node(
            decl_node_id, ast_nodes=[n], text=n.text.decode(), is_cond=False
        )
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], decl_node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([decl_node_id, "Uncond"])

        self.current_basic_block.add_cfg_nodes_ids(decl_node_id)
        self.current_basic_block.add_cfg_nodes(n)

    def visit_expression_statement(self, n: ts.Node):
        expr_node_id = self.get_node_id()
        self.cfg.add_node(
            expr_node_id, ast_nodes=[n], text=n.text.decode(), is_cond=False
        )
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], expr_node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([expr_node_id, "Uncond"])

        self.current_basic_block.add_cfg_nodes_ids(expr_node_id)
        self.current_basic_block.add_cfg_nodes(n)

    def visit_compound_statement(self, n: ts.Node):
        for compound_stmt_child in n.named_children:
            self.visit(compound_stmt_child)

    def visit_else_clause(self, n: ts.Node):
        for else_child in n.named_children:
            self.visit(else_child)

    def visit_if_statement(self, n: ts.Node):
        cond_node = n.named_child(0)
        cond_node_id = self.get_node_id()
        self.cfg.add_node(
            cond_node_id,
            ast_nodes=[cond_node],
            text=cond_node.text.decode(),
            is_cond=True,
        )
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], cond_node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([cond_node_id, "True"])

        self.current_basic_block.add_cfg_nodes_ids(cond_node_id)
        self.current_basic_block.add_cfg_nodes(cond_node)

        pred_basic_block = self.current_basic_block
        then_basic_block = self.new_basic_block()
        pred_basic_block.add_succ_id(then_basic_block.id)
        then_basic_block.add_pred_id(pred_basic_block.id)
        self.current_basic_block = then_basic_block

        then_node = n.named_child(1)
        self.visit(then_node)

        then_end_basic_block = self.current_basic_block

        if n.named_child_count > 2:
            old_preds = copy.deepcopy(self.preds)
            self.preds.clear()
            self.preds.append([cond_node_id, "False"])

            else_basic_block = self.new_basic_block()
            pred_basic_block.add_succ_id(else_basic_block.id)
            else_basic_block.add_pred_id(pred_basic_block.id)
            self.current_basic_block = else_basic_block

            alter_node = n.named_child(2)
            self.visit(alter_node)
            old_preds.extend(self.preds)
            self.preds = old_preds

            else_end_basic_block = self.current_basic_block
            follow_block = self.new_basic_block()

            if then_end_basic_block.link_to_follow_block():
                then_end_basic_block.add_succ_id(follow_block.id)
                follow_block.add_pred_id(then_end_basic_block.id)
            if else_end_basic_block.link_to_follow_block():
                else_end_basic_block.add_succ_id(follow_block.id)
                follow_block.add_pred_id(else_end_basic_block.id)

            self.current_basic_block = follow_block
        else:
            self.preds.append([cond_node_id, "False"])

            follow_block = self.new_basic_block()
            if then_end_basic_block.link_to_follow_block():
                then_end_basic_block.add_succ_id(follow_block.id)
                follow_block.add_pred_id(then_end_basic_block.id)

            pred_basic_block.add_succ_id(follow_block.id)
            follow_block.add_pred_id(pred_basic_block.id)
            self.current_basic_block = follow_block

    def visit_switch_statement(self, n: ts.Node):
        cond_node = n.named_child(0)
        cond_node_id = self.get_node_id()
        self.cfg.add_node(
            cond_node_id,
            ast_nodes=[cond_node],
            text=cond_node.text.decode(),
            is_cond=True,
        )
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], cond_node_id, condition=pred_id_info[1])
        self.preds.clear()

        self.current_basic_block.add_cfg_nodes_ids(cond_node_id)
        self.current_basic_block.add_cfg_nodes(cond_node)

        pred_basic_block = self.current_basic_block

        cases_node = n.named_child(1).named_children

        case_end_basic_block = None
        for case_node in cases_node:
            case_text = case_node.text.decode()
            case_text = case_text[: case_text.find(":") + 1]
            case_node_id = self.get_node_id()
            self.cfg.add_node(
                case_node_id, ast_nodes=[case_node], text=case_text, is_cond=True
            )
            self.cfg.add_edge(cond_node_id, case_node_id, condition="Uncond")
            self.preds.append([case_node_id, "True"])
            case_node_children = []

            case_basic_block = self.new_basic_block()
            pred_basic_block.add_succ_id(case_basic_block.id)
            case_basic_block.add_pred_id(pred_basic_block.id)
            case_basic_block.add_cfg_nodes_ids(case_node_id)
            case_basic_block.add_cfg_nodes(case_node)

            case_child_basic_block = self.new_basic_block()
            case_basic_block.add_succ_id(case_child_basic_block.id)
            case_child_basic_block.add_pred_id(case_basic_block.id)

            self.current_basic_block = case_child_basic_block
            if (
                case_end_basic_block != None
                and case_end_basic_block.link_to_follow_block()
            ):
                case_end_basic_block.add_succ_id(self.current_basic_block.id)
                self.current_basic_block.add_pred_id(case_end_basic_block.id)

            if "default" in case_text:
                case_node_children = case_node.children
            else:
                case_node_children = case_node.children[1:]

            for case_node_child in case_node_children:
                self.visit(case_node_child)

            case_end_basic_block = self.current_basic_block

        self.preds.extend(self.break_preds)
        self.break_preds = []

        switch_end_basic_block = self.current_basic_block
        follow_basic_block = self.new_basic_block()
        switch_end_basic_block.add_succ_id(follow_basic_block.id)
        follow_basic_block.add_pred_id(switch_end_basic_block.id)

        for break_basic_block in self.break_basic_blocks:
            break_basic_block.add_succ_id(follow_basic_block.id)
            follow_basic_block.add_pred_id(break_basic_block.id)

        self.current_basic_block = follow_basic_block
        self.break_basic_blocks.clear()

    def visit_do_statement(self, n: ts.Node):
        dummy_node_id = self.get_node_id()
        self.cfg.add_node(dummy_node_id, ast_nodes=[], text="dummy", is_cond=False)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], dummy_node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([dummy_node_id, "Uncond"])

        do_basic_block = self.new_basic_block()
        self.current_basic_block.add_succ_id(do_basic_block.id)
        do_basic_block.add_pred_id(self.current_basic_block.id)

        self.current_basic_block = do_basic_block
        self.current_basic_block.add_cfg_nodes_ids(dummy_node_id)

        self.visit(n.child_by_field_name("body"))
        cond = n.child_by_field_name("condition")
        cond_id = self.get_node_id()
        self.cfg.add_node(
            cond_id, ast_nodes=[cond], text=cond.text.decode(), is_cond=True
        )
        self.cfg.add_edge(cond_id, dummy_node_id, condition="True")
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], cond_id, condition=pred_id_info[1])
        self.preds.clear()

        for continue_pred_info in self.continue_preds:
            self.cfg.add_edge(
                continue_pred_info[0], cond_id, condition=continue_pred_info[1]
            )
        self.continue_preds.clear()

        self.preds.append([cond_id, "False"])
        self.preds.extend(self.break_preds)
        self.break_preds.clear()

        do_end_basic_block = self.current_basic_block
        cond_basic_block = self.new_basic_block()
        cond_basic_block.add_cfg_nodes_ids(cond_id)
        cond_basic_block.add_cfg_nodes(cond)

        cond_basic_block.add_succ_id(do_basic_block.id)
        do_basic_block.add_pred_id(cond_basic_block.id)
        do_end_basic_block.add_succ_id(cond_basic_block.id)
        cond_basic_block.add_pred_id(do_end_basic_block.id)

        for continue_basic_block in self.continue_basic_blocks:
            continue_basic_block.add_succ_id(cond_basic_block.id)
            cond_basic_block.add_pred_id(continue_basic_block.id)

        self.continue_basic_blocks.clear()

        follow_block = self.new_basic_block()
        cond_basic_block.add_succ_id(follow_block.id)
        follow_block.add_pred_id(cond_basic_block.id)

        for break_basic_block in self.break_basic_blocks:
            break_basic_block.add_succ_id(follow_block.id)
            follow_block.add_pred_id(break_basic_block.id)

        self.current_basic_block = follow_block
        self.break_basic_blocks.clear()

    def visit_while_statement(self, n: ts.Node):
        cond_node = n.named_child(0)
        cond_node_id = self.get_node_id()
        self.cfg.add_node(
            cond_node_id,
            ast_nodes=[cond_node],
            text=cond_node.text.decode(),
            is_cond=True,
        )
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], cond_node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([cond_node_id, "True"])

        pred_basic_block = self.new_basic_block()
        pred_basic_block.add_cfg_nodes_ids(cond_node_id)
        pred_basic_block.add_cfg_nodes(cond_node)

        self.current_basic_block.add_succ_id(pred_basic_block.id)
        pred_basic_block.add_pred_id(self.current_basic_block.id)
        self.current_basic_block = pred_basic_block

        then_basic_block = self.new_basic_block()
        pred_basic_block.add_succ_id(then_basic_block.id)
        then_basic_block.add_pred_id(pred_basic_block.id)
        self.current_basic_block = then_basic_block

        compound_statement = n.named_child(1)
        self.visit(compound_statement)

        then_end_basic_block = self.current_basic_block

        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], cond_node_id, condition=pred_id_info[1])
        self.preds = []

        for continue_pred_id_info in self.continue_preds:
            self.cfg.add_edge(
                continue_pred_id_info[0],
                cond_node_id,
                condition=continue_pred_id_info[1],
            )

        for continue_basic_block in self.continue_basic_blocks:
            pred_basic_block.add_pred_id(continue_basic_block.id)
            continue_basic_block.add_succ_id(pred_basic_block.id)

        follow_block = self.new_basic_block()

        pred_basic_block.add_succ_id(follow_block.id)
        follow_block.add_pred_id(pred_basic_block.id)

        then_end_basic_block.add_succ_id(pred_basic_block.id)
        pred_basic_block.add_pred_id(then_end_basic_block.id)

        for break_basic_block in self.break_basic_blocks:
            follow_block.add_pred_id(break_basic_block.id)
            break_basic_block.add_succ_id(follow_block.id)

        self.current_basic_block = follow_block
        self.break_basic_blocks.clear()
        self.continue_basic_blocks.clear()

        self.continue_preds.clear()
        self.preds.append([cond_node_id, "False"])
        self.preds.extend(self.break_preds)
        self.break_preds.clear()

    def visit_for_statement(self, n: ts.Node):
        has_init = False
        init_node = None
        has_cond = False
        cond_node = None
        cond_node_id = None
        has_update = False
        update_node = None

        if n.child_by_field_name("initializer") is not None:
            has_init = True
            init_node = n.child_by_field_name("initializer")
        if n.child_by_field_name("condition") is not None:
            has_cond = True
            cond_node = n.child_by_field_name("condition")
        if n.child_by_field_name("update") is not None:
            has_update = True
            update_node = n.child_by_field_name("update")

        if has_init:
            init_node_id = self.get_node_id()
            self.cfg.add_node(
                init_node_id,
                ast_nodes=[init_node],
                text=init_node.text.decode(),
                is_cond=False,
            )
            for pred_id_info in self.preds:
                self.cfg.add_edge(
                    pred_id_info[0], init_node_id, condition=pred_id_info[1]
                )
            self.preds.clear()
            self.preds.append([init_node_id, "Uncond"])

            self.current_basic_block.add_cfg_nodes_ids(init_node_id)
            self.current_basic_block.add_cfg_nodes(init_node)

        cond_basic_block = self.new_basic_block()
        if has_cond:
            cond_node_id = self.get_node_id()
            self.cfg.add_node(
                cond_node_id,
                ast_nodes=[cond_node],
                text=cond_node.text.decode(),
                is_cond=True,
            )
            for pred_id_info in self.preds:
                self.cfg.add_edge(
                    pred_id_info[0], cond_node_id, condition=pred_id_info[1]
                )
            self.preds.clear()
            self.preds.append([cond_node_id, "True"])

            cond_basic_block.add_cfg_nodes_ids(cond_node_id)
            cond_basic_block.add_cfg_nodes(cond_node)

        else:
            cond_node_id = self.get_node_id()
            self.cfg.add_node(cond_node_id, ast_nodes=[], text="True", is_cond=True)
            for pred_id_info in self.preds:
                self.cfg.add_edge(
                    pred_id_info[0], cond_node_id, condition=pred_id_info[1]
                )
            self.preds.clear()
            self.preds.append([cond_node_id, "True"])

            cond_basic_block.add_cfg_nodes_ids(cond_node_id)

        self.current_basic_block.add_succ_id(cond_basic_block.id)
        cond_basic_block.add_pred_id(self.current_basic_block.id)

        body_basic_block = self.new_basic_block()
        cond_basic_block.add_succ_id(body_basic_block.id)
        body_basic_block.add_pred_id(cond_basic_block.id)

        self.current_basic_block = body_basic_block
        compound_statement = n.child_by_field_name("body")
        self.visit(compound_statement)

        if has_update:
            update_basic_block = self.new_basic_block()
            update_node_id = self.get_node_id()
            self.cfg.add_node(
                update_node_id,
                ast_nodes=[update_node],
                text=update_node.text.decode(),
                is_cond=False,
            )
            for pred_id_info in self.preds:
                self.cfg.add_edge(
                    pred_id_info[0], update_node_id, condition=pred_id_info[1]
                )
            self.preds.clear()
            self.cfg.add_edge(update_node_id, cond_node_id, condition="Uncond")
            for continue_node_info in self.continue_preds:
                self.cfg.add_edge(
                    continue_node_info[0],
                    update_node_id,
                    condition=continue_node_info[1],
                )
            self.continue_preds.clear()

            update_basic_block.add_cfg_nodes_ids(update_node_id)
            update_basic_block.add_cfg_nodes(update_node)

            body_end_basic_block = self.current_basic_block
            body_end_basic_block.add_succ_id(update_basic_block.id)
            update_basic_block.add_pred_id(body_end_basic_block.id)

            update_basic_block.add_succ_id(cond_basic_block.id)
            cond_basic_block.add_pred_id(update_basic_block.id)

            for continue_basic_block in self.continue_basic_blocks:
                continue_basic_block.add_succ_id(update_basic_block.id)
                update_basic_block.add_pred_id(continue_basic_block.id)

        else:
            for pred_id_info in self.preds:
                self.cfg.add_edge(
                    pred_id_info[0], cond_node_id, condition=pred_id_info[1]
                )
            self.preds.clear()
            for continue_node_info in self.continue_preds:
                self.cfg.add_edge(
                    continue_node_info[0], cond_node_id, condition=continue_node_info[1]
                )
            self.continue_preds.clear()

            body_end_basic_block = self.current_basic_block
            body_end_basic_block.add_succ_id(cond_basic_block.id)
            cond_basic_block.add_pred_id(body_end_basic_block.id)

            for continue_basic_block in self.continue_basic_blocks:
                continue_basic_block.add_succ_id(cond_basic_block.id)
                cond_basic_block.add_pred_id(continue_basic_block.id)

        self.preds.append([cond_node_id, "False"])
        self.preds.extend(self.break_preds)
        self.break_preds.clear()

        follow_basic_block = self.new_basic_block()
        for break_basic_block in self.break_basic_blocks:
            break_basic_block.add_succ_id(follow_basic_block.id)
            follow_basic_block.add_pred_id(break_basic_block.id)

        cond_basic_block.add_succ_id(follow_basic_block.id)
        follow_basic_block.add_pred_id(cond_basic_block.id)

        self.break_basic_blocks.clear()
        self.continue_basic_blocks.clear()
        self.current_basic_block = follow_basic_block

    def visit_break_statement(self, n: ts.Node):
        node_id = self.get_node_id()
        self.cfg.add_node(node_id, ast_nodes=[n], text=n.text.decode(), is_cond=True)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.break_preds.append([node_id, "Uncond"])

        self.current_basic_block.add_cfg_nodes_ids(node_id)
        self.current_basic_block.add_cfg_nodes(n)

        self.current_basic_block.set_break(True)
        self.break_basic_blocks.append(self.current_basic_block)

    def visit_continue_statement(self, n: ts.Node):
        node_id = self.get_node_id()
        self.cfg.add_node(node_id, ast_nodes=[n], text=n.text.decode(), is_cond=True)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.continue_preds.append([node_id, "Uncond"])

        self.current_basic_block.add_cfg_nodes_ids(node_id)
        self.current_basic_block.add_cfg_nodes(n)
        self.current_basic_block.set_continue(True)
        self.continue_basic_blocks.append(self.current_basic_block)

    def visit_return_statement(self, n: ts.Node):
        node_id = self.get_node_id()
        self.cfg.add_node(node_id, ast_nodes=[n], text=n.text.decode(), is_cond=True)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.current_basic_block.add_cfg_nodes_ids(node_id)
        self.current_basic_block.add_cfg_nodes(n)
        self.current_basic_block.set_return(True)

    def visit_labeled_statement(self, n: ts.Node):
        pred_basic_block = self.current_basic_block
        self.current_basic_block = self.new_basic_block()
        self.labeled_basic_blocks.append(self.current_basic_block)

        pred_basic_block.add_succ_id(self.current_basic_block.id)
        self.current_basic_block.add_pred_id(pred_basic_block.id)

        node_id = self.get_node_id()
        self.current_basic_block.set_labelstmt_node(node_id)
        label_text = n.text.decode()
        label_text = label_text[: label_text.find(":") + 1]
        self.cfg.add_node(node_id, ast_nodes=[n], text=label_text, is_cond=True)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], node_id, condition=pred_id_info[1])
        self.preds.clear()
        self.preds.append([node_id, "Uncond"])
        label_node = n.child_by_field_name("label")
        self.labels[label_node.text.decode()] = node_id

        self.current_basic_block.add_cfg_nodes_ids(node_id)
        self.current_basic_block.add_cfg_nodes(n)

        if n.child_count > 1:
            for label_stmt_child in n.named_children[1:]:
                self.visit(label_stmt_child)

    def visit_goto_statement(self, n: ts.Node):
        node_id = self.get_node_id()
        self.cfg.add_node(node_id, ast_nodes=[n], text=n.text.decode(), is_cond=True)
        for pred_id_info in self.preds:
            self.cfg.add_edge(pred_id_info[0], node_id, condition=pred_id_info[1])
        self.preds.clear()

        label_node = n.child_by_field_name("label")
        if label_node.text.decode() not in self.gotos:
            self.gotos[label_node.text.decode()] = []
        self.gotos[label_node.text.decode()].append(node_id)

        self.current_basic_block.add_cfg_nodes_ids(node_id)
        self.current_basic_block.add_cfg_nodes(n)
        self.current_basic_block.set_goto(True)
        self.current_basic_block.set_goto_node(node_id)
        self.goto_basic_blocks.append(self.current_basic_block)

    def visit_default(self, n: ts.Node):
        pass

    def get_node_id(self):
        id_ = self.id
        self.id = self.id + 1
        return id_

    def new_basic_block(self):
        id_ = self.basic_block_id
        self.basic_block_id = self.basic_block_id + 1
        new_basic_block = Basic_block(id_)
        self.basic_blocks[id_] = new_basic_block
        return new_basic_block

    def dump_basic_blocks(self):
        for id, basic_block in self.basic_blocks.items():
            print(f"{id}:")
            for cfg_node_id in basic_block.get_cfg_nodes_ids():
                cfg_node = self.cfg.nodes[cfg_node_id]
                print(cfg_node["text"])
            print(f"preds:{basic_block.get_preds_ids()}")
            print(f"succs:{basic_block.get_succs_ids()}")

    def get_basic_block(self, id):
        return self.basic_blocks[id]

    def get_path_str(self, basic_blocks):
        path_str = ""
        for basic_block in basic_blocks:
            for cfg_node_id in basic_block.get_cfg_nodes_ids():
                cfg_node = self.cfg.nodes[cfg_node_id]
                path_str = path_str + cfg_node["text"] + "\n"
        return path_str

    # for a node id, determine whether it is related to cond
    def get_node_info(self, node_id):
        return self.cfg.nodes[node_id]

    def get_edge_info(self, node_id1, node_id2):
        if node_id1 in self.cfg and node_id2 in self.cfg[node_id1]:
            return self.cfg[node_id1][node_id2]
        return None

    def get_basic_block_str(self, basic_block):
        block_str = ""
        for cfg_node_id in basic_block.get_cfg_nodes_ids():
            cfg_node = self.cfg.nodes[cfg_node_id]
            block_str = block_str + cfg_node["text"] + "\n"
        return block_str


# # %%
# from tree_sitter import Language, Parser
# import tree_sitter as ts

# C_LANGUAGE = Language("build/my-languages.so", "c")
# c_parser = Parser()
# c_parser.set_language(C_LANGUAGE)
# c_code_snippet = """
# """
# with open("./test.c") as f:
#     c_code_snippet = f.read()
# tree = c_parser.parse(bytes(c_code_snippet, "utf8"))
# root_node = tree.root_node


# # %%
# for root_node_child in root_node.named_children:
#     if root_node_child.type == "function_definition":
#         cfg = CFG(root_node_child).cfg
#         CFG(root_node_child).dump_basic_blocks()
#         cfg1 = CFG(root_node_child)


# # %% [markdown]
# #

# # %%
# node_labels = {node: data["text"] for node, data in cfg.nodes(data=True)}


# # %%
# pos = nx.nx_agraph.graphviz_layout(cfg, prog="dot")


# # %%
# nx.draw(
#     cfg,
#     pos,
#     with_labels=True,
#     labels=node_labels,
#     node_size=50,
#     node_color="skyblue",
#     font_size=5,
#     font_color="black",
#     arrowsize=5,
# )

# # edge_labels = nx.get_edge_attributes(cfg, "condition")
# # nx.draw_networkx_edge_labels(
# #     cfg, pos, edge_labels=edge_labels, font_color="black", font_size=5
# # )
