#ifndef DETECT_HOOK_INDIRECT_TAINT_H
#define DETECT_HOOK_INDIRECT_TAINT_H

/* 间接污染污染区记录结构 */
typedef struct {
	PyFrameObject *frame;   // 所属栈帧
	int opcode_index_begin; // 污染区的起始opcode
	int opcode_index_end;   // 污染区的结束opcode
} DETECT_INDIRECT_TAINT_AREA_T;

extern void detect_hook_indirect_taint_set_area(PyFrameObject *frame, int opcode, int oparg);
extern void detect_hook_indirect_taint_pop_area(PyFrameObject *frame, int opcode, int skip_count);
extern void detect_hook_indirect_taint_init();

#endif

