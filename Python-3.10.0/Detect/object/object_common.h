#ifndef DETECT_OBJECT_COMMON_H
#define DETECT_OBJECT_COMMON_H

#include <stdbool.h>

/* 对象类型, 取值顺序代表了污染传递的优先级，值越低优先级越高 */
typedef enum detect_object_type{
	DETECT_OBJECT_TYPE_TAINT = 0,  // taint类型的对象
	DETECT_OBJECT_TYPE_THREAT,     // threat类型的对象
	DETECT_OBJECT_TYPE_CUSTOM,     // custom类型的对象
	DETECT_OBJECT_TYPE_UNDEF,      // undefined类型的对象
	DETECT_OBJECT_TYPE_MAX
}DETECT_OBJECT_TYPE;

/* hook对象结构体header */
#define HOOK_OBJECT_HEAD \
	PyObject_HEAD \
	PyObject *config_dict;          /* 配置字典 */ \
	PyObject *original_hooked_obj;  /* 原始的被hook的对象 */ \
	Py_ssize_t iter_count;          /* 记录对象的迭代次数 */ \

/* hook对象的header结构体 */
typedef struct {
	HOOK_OBJECT_HEAD
} PyHookObject;

extern int detect_object_init();
extern bool detect_object_object_is_taint(PyObject *object);
extern bool detect_object_object_is_threat(PyObject *object);
extern bool detect_object_object_is_custom(PyObject *object);
extern bool detect_object_object_is_undef(PyObject *object);
extern DETECT_OBJECT_TYPE detect_object_get_object_type(PyObject *object);
extern int detect_object_create_subclass(PyTypeObject *parent_class, 
										 PyObject *config_classes_dict, 
										 const char *class_name_prefix);
extern int detect_object_create_hook_objects(PyTypeObject *class, 
								      PyObject *config_classes_dict);
extern PyObject* detect_object_get_highest_priority_item_by_args_and_kwargs(PyObject *args, 
																		PyObject *kwargs);

/* 通用模式方法实现函数 */
extern PyObject *detect_object_class_getattro(PyObject *obj, PyObject *name);
extern int detect_object_class_setattro(PyObject *obj, PyObject *name, PyObject *value);
extern PyObject *detect_object_class_call(PyObject *obj, PyObject *args, PyObject *kwargs);
extern void detect_object_class_dealloc(PyObject *self);
extern PyObject* detect_object_class_iter(PyObject *self);
extern PyObject* detect_object_class_iternext(PyObject *self);
extern PyObject* detect_object_class_repr(PyObject *self);
extern PyObject* detect_object_class_str(PyObject *self);

#endif

