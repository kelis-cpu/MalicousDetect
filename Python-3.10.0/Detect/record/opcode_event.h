#ifndef DETECT_RECORD_OPCODE_EVENT_H
#define DETECT_RECORD_OPCODE_EVENT_H

#include <stdbool.h>
#include "Detect/configs/config.h"
#include "Detect/object/object.h"

/* 可调用对象基本信息 */
typedef struct {
	PyObject *module_name;        // 可调用对象所属模块名
	PyObject *class_name;         // 可调用对象为class或method时的类名
	PyObject *method_name;        // 可调用对象为method时的方法名
	PyObject *func_name;          // 可调用对象为func时的函数名
	DETECT_OBJECT_TYPE hook_object_type;       // 可调用对象的hook类型
	DETECT_CONFIG_OBJ_TYPE config_object_type; // 可调用对象的配置类型
	DETECT_THREAT_TYPE_E threat_type; // 如果可调用对象是威胁对象，那么该字段为威胁类型
} DETECT_RECORD_CALLABLE_INFO_T;

/* 可调用对象的调用结构 */
typedef struct {
	DETECT_RECORD_CALLABLE_INFO_T callable_info; // 可调用对象基本信息
	PyObject **stack_pointer;     // 当前frame栈顶指针，用于获取参数
	int opcode;
	int oparg;
	int line_no;                  // 调用行号
	bool is_avaliable;            // 当前结构中的信息是否是有效的，使用该结构前需要判断该字段
} DETECT_RECORD_CALL_INFO_T;

/* 执行信息结构 */
typedef struct {
	DETECT_RECORD_CALL_INFO_T cur_call_info; // 当前可调用对象的调用信息
} DETECT_RECORD_INFO_T;

extern int detect_record_opcode_event_proc(PyFrameObject *frame, int what, PyObject *arg);
extern DETECT_RECORD_INFO_T* detect_record_get_record_info();

#endif

