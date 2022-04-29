#ifndef DETECT_HOOK_OPCODE_PREV_HANDLERS_H
#define DETECT_HOOK_OPCODE_PREV_HANDLERS_H

extern int detect_hook_opcode_unary_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_binary_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int opcode, int oparg);
extern int detect_hook_opcode_import_name_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_import_from_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_import_star_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_call_function_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_call_function_kw_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_call_function_ex_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_call_method_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_return_value_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_unpack_sequence_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_jump_forward_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_pop_jump_if_false_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_pop_jump_if_true_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_jump_absolute_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_contains_op_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_pop_top_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_setup_finally_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_pop_except_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_pop_block_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_reraise_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);
extern int detect_hook_opcode_dup_top_prev_handler(PyThreadState *tstate, PyObject ***stack_pointer_addr, int oparg);

#endif
