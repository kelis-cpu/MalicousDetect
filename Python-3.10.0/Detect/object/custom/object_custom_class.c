/*
 * @Description: custom类和子类实现和初始化，custom子类作为需要自定义处理逻辑的类的hook对象
 */
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/object/custom/object_custom_class.h"
#include "Detect/configs/config.h"
#include "Detect/utils/dict.h"
#include "Detect/utils/exception.h"

/**
 * @description: custom类的__call__方法实现，所有custom对象的调用会执行该函数
 * @param obj 对象
 * @param name 属性名
 * @param value 值
 * @return int
 */
static PyObject *detect_object_custom_class_method_call(PyObject *obj, PyObject *args, PyObject *kwargs) {
	PyCustomObject *custom_obj = (PyCustomObject *)obj;
	PyObject *res;
	custom_func pfunc;

	/* 获取自定义逻辑处理函数 */
	pfunc = PyLong_AsVoidPtr(PyDict_GetItemString(custom_obj->config_dict, CUSTOM_FUNC_STRING));

	/* 调用自定义逻辑处理函数 */
	res = pfunc(obj, custom_obj->original_hooked_obj, args, kwargs);

	/* 如果调用过程中发生异常，在CALL_FUNCTION opcode处理 */
    return res;
}

/**
 * @description: custom类的__new__方法实现，所有custom对象的生成会调用该函数
 * @param type 类型对象
 * @param args 位置参数
 * @param kwargs 关键字参数
 * @return PyObject* 生成的对象
 */
static PyObject *detect_object_custom_class_method_new(PyTypeObject *type, PyObject *args, PyObject *kwargs) {
	PyCustomObject *custom_obj;

    custom_obj = (PyCustomObject *)type->tp_alloc(type, 0);

	if (PyType_IsSubtype(type, &PyCustom_Type) && type != &PyCustom_Type) { // type为custom类的子类, 此时为custom子类的实例化操作
		custom_obj->config_dict = PyObject_GetAttrString((PyObject *)type, CONFIG_DICT_STRING);
	} else { // type为custom类
		/* custom类的实例对象在外面自行初始化 */
	}

	return (PyObject *)custom_obj;
}

/* 
 * custom类实现，该类作为所有custom子类的父类. custom类为静态类，因此不能在外部添加
 * 和修改类属性，所有属性需在此处静态定义.
 */
PyTypeObject PyCustom_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    .tp_name       = CUSTOM_CLASS_PREFIX,
    .tp_basicsize  = sizeof(PyCustomObject),
    .tp_itemsize   = 0,
    .tp_getattro   = detect_object_class_getattro,
    .tp_setattro   = detect_object_class_setattro,
    .tp_iter       = detect_object_class_iter,
    .tp_iternext   = detect_object_class_iternext,
    .tp_new        = detect_object_custom_class_method_new,
    .tp_free       = PyObject_Free,
    .tp_dealloc    = detect_object_class_dealloc,
    .tp_call       = detect_object_custom_class_method_call,
    .tp_alloc      = PyType_GenericAlloc, // 该申请函数会先将对象memset 0后再做初始化
    .tp_init       = NULL,                // 不设置__init__
	.tp_dictoffset = 0,                   // 实例对象中不设置__dict__属性
    .tp_flags      = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, // 允许custom类被继承
    .tp_repr       = detect_object_class_repr,
	.tp_str        = detect_object_class_str,
};

/**
 * @description: custom类初始化
 * @return void
 */
int detect_object_custom_class_init() {
	int ret = 0;

	/* 初始化custom类 */
	ret = PyType_Ready(&PyCustom_Type);

	/* 根据自定义类的配置表创建对应的custom子类 */
	ret = detect_object_create_subclass(&PyCustom_Type, g_custom_class_dict, CUSTOM_CLASS_PREFIX);

	return ret;
}

