#ifndef DETECT_HOOK_OPCODE_H
#define DETECT_HOOK_OPCODE_H

extern int detect_hook_opcode_prev_handler(PyThreadState *frame, PyObject ***stack_pointer, int opcode, int oparg);
extern int detect_hook_opcode_after_handler(PyThreadState *frame, PyObject ***stack_pointer, int opcode, int oparg);

/* opcode处理前函数在虚拟机的dispatch_opcode标签下调用 */
#define DETECT_OPCODE_PREV_HANDLE(tstate, stack_pointer_addr, opcode, oparg) \
	do { \
        int skip_count = detect_hook_opcode_prev_handler(tstate, stack_pointer_addr, opcode, oparg); \
		if (skip_count > 0) { \
			/* 跳过包括当前opcode的后续skip_count个opcode的执行 */ \
			JUMPBY(skip_count-1); \
			goto tracing_dispatch; \
		} else if (skip_count < 0) { \
			assert(0); \
		} \
    } while (0)

/* 在DISPATCH宏的入口处调用 */
#define DETECT_OPCODE_AFTER_HANDLE(tstate, stack_pointer_addr, opcode, oparg) \
	do { \
		int skip_count = detect_hook_opcode_after_handler(tstate, stack_pointer_addr, opcode, oparg); \
		if (skip_count > 0) { \
			/* 跳过包括当前opcode的后续skip_count个opcode的执行 */ \
			JUMPBY(skip_count); \
			goto tracing_dispatch; \
		} else if (skip_count < 0) { \
			assert(0); \
		} \
	} while (0)


#endif

