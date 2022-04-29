/*
 * @Description: threat类和子类实现和初始化，threat子类作为威胁类的hook对象，
 *               threat类的对象作为威胁方法和威胁函数的hook对象。
 */
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/object/threat/object_threat_class.h"
#include "Detect/configs/config.h"
#include "Detect/utils/dict.h"
#include "Detect/utils/exception.h"

/**
 * @description: threat类的__call__方法实现，所有threat对象的调用会执行该函数
 * @param obj 对象
 * @param name 属性名
 * @param value 值
 * @return int
 */
static PyObject *detect_object_threat_class_method_call(PyObject *obj, PyObject *args, PyObject *kwargs) {
	PyThreatObject *threat_obj = (PyThreatObject *)obj;
	PyObject *res = obj;
	PyObject *highest_priority_param = detect_object_get_highest_priority_item_by_args_and_kwargs(args, kwargs);

	/* 判断是否需要执行原处理逻辑 */
	if (PyDict_GetItemString(threat_obj->config_dict, NEED_EXECUTE_STRING) == Py_True) {
		res = PyObject_Call(threat_obj->original_hooked_obj, args, kwargs);

		/* 发生了异常 */
		if (res == NULL && PyErr_Occurred()) {
			PyErr_Clear();

			if (detect_object_get_object_type(highest_priority_param) < DETECT_OBJECT_TYPE_THREAT) {
				res = highest_priority_param;
			} else {
				res = obj;
			}
		}
	} else {
		if (detect_object_get_object_type(highest_priority_param) < DETECT_OBJECT_TYPE_THREAT) {
			res = highest_priority_param;
		} else {
			res = obj;
		}
	}

	Py_INCREF(res);
    return res;
}

/**
 * @description: threat类的__new__方法实现，所有threat对象的生成会调用该函数
 * @param type 类型对象
 * @param args 位置参数
 * @param kwargs 关键字参数
 * @return PyObject* 生成的对象
 */
static PyObject *detect_object_threat_class_method_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
	PyThreatObject *threat_obj;

    threat_obj = (PyThreatObject *)type->tp_alloc(type, 0);

	if (PyType_IsSubtype(type, &PyThreat_Type) && type != &PyThreat_Type) { // type为threat类的子类, 此时为threat子类的实例化操作
		threat_obj->config_dict = PyObject_GetAttrString((PyObject *)type, CONFIG_DICT_STRING);
	} else { // type为threat类
		/* threat类的实例对象在外面自行初始化 */
	}

	return (PyObject *)threat_obj;
}


/* 
 * threat类实现，该类作为所有threat子类的父类. threat类为静态类，因此不能在外部添加
 * 和修改类属性，所有属性需在此处静态定义.
 */
PyTypeObject PyThreat_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    .tp_name       = THREAT_CLASS_PREFIX,
    .tp_basicsize  = sizeof(PyThreatObject),
    .tp_itemsize   = 0,
    .tp_getattro   = detect_object_class_getattro,
    .tp_setattro   = detect_object_class_setattro,
    .tp_iter       = detect_object_class_iter,
    .tp_iternext   = detect_object_class_iternext,
    .tp_new        = detect_object_threat_class_method_new,
    .tp_free       = PyObject_Free,
    .tp_dealloc    = detect_object_class_dealloc,
    .tp_call       = detect_object_threat_class_method_call,
    .tp_alloc      = PyType_GenericAlloc, // 该申请函数会先将对象memset 0后再做初始化
    .tp_init       = NULL,                // 不设置__init__
	.tp_dictoffset = 0,                   // 实例对象中不设置__dict__属性
    .tp_flags      = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, // 允许threat类被继承
    .tp_repr       = detect_object_class_repr,
	.tp_str        = detect_object_class_str,
};



/**
 * @description: threat类初始化
 * @return void
 */
int detect_object_threat_class_init() {
	int ret = 0;

	/* 初始化threat类 */
	ret = PyType_Ready(&PyThreat_Type);

	/* 根据威胁类的配置表创建对应的threat子类 */
	ret = detect_object_create_subclass(&PyThreat_Type, g_threat_class_dict, THREAT_CLASS_PREFIX);

	return ret;
}


