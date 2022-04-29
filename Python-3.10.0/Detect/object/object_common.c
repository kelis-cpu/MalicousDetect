/*
 * @Description: 提供taint、threat、undef类的一些通用操作
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/utils/dict.h"

/**
  * @description: 判断给定对象是否为taint类的子类或者是其实例化对象
  * @param object 待判断对象
  */
bool detect_object_object_is_taint(PyObject *object) {
	bool res = false;

	if (PyType_CheckExact(object)) {
		/* 类型对象，判断是否为其子类 */
		res = PyObject_IsSubclass(object, (PyObject *)&PyTaint_Type) == 1 ? true : false;
	} else {
		/* 实例对象，判断是否为其实例化对象 */
		res = PyObject_IsInstance(object, (PyObject *)&PyTaint_Type) == 1 ? true : false;
	}

	return res;
}

/**
  * @description: 判断给定对象是否为threat类的子类或者是其实例化对象
  * @param object 待判断对象
  */
bool detect_object_object_is_threat(PyObject *object) {
	bool res = false;

	if (PyType_CheckExact(object)) {
		/* 类型对象，判断是否为其子类 */
		res = PyObject_IsSubclass(object, (PyObject *)&PyThreat_Type) == 1 ? true : false;
	} else {
		/* 实例对象，判断是否为其实例化对象 */
		res = PyObject_IsInstance(object, (PyObject *)&PyThreat_Type) == 1 ? true : false;
	}

	return res;
}

/**
  * @description: 判断给定对象是否为custom类的子类或者是其实例化对象
  * @param object 待判断对象
  */
bool detect_object_object_is_custom(PyObject *object) {
	bool res = false;

	if (PyType_CheckExact(object)) {
		/* 类型对象，判断是否为其子类 */
		res = PyObject_IsSubclass(object, (PyObject *)&PyCustom_Type) == 1 ? true : false;
	} else {
		/* 实例对象，判断是否为其实例化对象 */
		res = PyObject_IsInstance(object, (PyObject *)&PyCustom_Type) == 1 ? true : false;
	}

	return res;
}

/**
  * @description: 判断给定对象是否为undef类的子类或者是其实例化对象
  * @param object 待判断对象
  */
bool detect_object_object_is_undef(PyObject *object) {
	bool res = false;
	
	if (PyType_CheckExact(object)) {
		/* 类型对象，判断是否为其子类 */
		res = PyObject_IsSubclass(object, (PyObject *)&PyUndef_Type) == 1 ? true : false;
	} else {
		/* 实例对象，判断是否为其实例化对象 */
		res = PyObject_IsInstance(object, (PyObject *)&PyUndef_Type) == 1 ? true : false;
	}

	return res;
}

/**
  * @description: 获取给定对象的类型
  * @param object 给定对象
  */
DETECT_OBJECT_TYPE detect_object_get_object_type(PyObject *object) {
	DETECT_OBJECT_TYPE obj_type = DETECT_OBJECT_TYPE_MAX;

	if (NULL == object) {
		return obj_type;
	}

	if (detect_object_object_is_taint(object)) {
		obj_type = DETECT_OBJECT_TYPE_TAINT;
	} else if (detect_object_object_is_threat(object)) {
		obj_type = DETECT_OBJECT_TYPE_THREAT;
	} else if (detect_object_object_is_custom(object)) {
		obj_type = DETECT_OBJECT_TYPE_CUSTOM;
	} else if (detect_object_object_is_undef(object)) {
		obj_type = DETECT_OBJECT_TYPE_UNDEF;
	} else {
		obj_type = DETECT_OBJECT_TYPE_MAX;
	}

	return obj_type;
}

/**
  * @description: 根据单个类的配置字典构造创建子类时创建需要的参数元组,
  * 			  元组元素为("类名", (父类元组), {属性列表}) 
  * @param parent_class 父类
  * @param config_class_dict 要创建的子类的单个配置字典
  * @param class_name_prefix 子类类名的前缀
  * @return 参数元组
  */
static PyObject *detect_object_create_subclass_tuple_args(PyTypeObject *parent_class, 
 													       PyObject *config_class_dict,
 													       const char *class_name_prefix) {
	PyObject *args = PyTuple_New(3);  // 参数元组
	PyObject *bases = PyTuple_New(1); // 父类元组
	PyObject *dict = PyDict_New();    // 类属性列表
	 
	/* taint子类名设置为"taint_class_模块名__类名" */
	PyTuple_SET_ITEM(args, 0, 
	            	PyUnicode_FromFormat("%s_%s__%s", 
					class_name_prefix,
					dict_getitem_string_string(config_class_dict, MODULE_NAME_STRING),
					dict_getitem_string_string(config_class_dict, CLASS_NAME_STRING)));
 
	/* 设置父类为指定的类 */
	PyTuple_SET_ITEM(bases, 0, (PyObject*)parent_class);
	PyTuple_SET_ITEM(args, 1, bases);
 
	/* 设置子类的类属性, 添加配置字典 */
	dict_setitem_string_object(dict, CONFIG_DICT_STRING, config_class_dict);
 
	PyTuple_SET_ITEM(args, 2, dict);
 
	return args;
}
 
/**
  * @description: 根据类的配置表创建对应的子类, 然后将创建的子类添加到类的配置表中.
  * @param parent_class 父类
  * @param config_class_dict 要创建的子类的配置表
  * @param class_name_prefix 子类类名的前缀
  * @return int
  */
int detect_object_create_subclass(PyTypeObject *parent_class, 
										 PyObject *config_classes_dict, 
										 const char *class_name_prefix) {
	Py_ssize_t i = 0;
	PyObject *key, *value;
	PyObject *subclass;
	PyObject *init_args_tuple;
	int ret = 0;

    /**
   	  *相当于在python层执行类似于type('MyClass', (), {'data': 1})
   	  * 来动态创建子类
      */
	while (PyDict_Next(config_classes_dict, &i, &key, &value)) {
	
		/* 构造PyType_Type.tp_new的参数元组 */
		PyObject *args = detect_object_create_subclass_tuple_args(parent_class, value, class_name_prefix);
 
		/* 创建子类，调用type.__new__ */
		subclass = PyType_Type.tp_new(&PyType_Type, args, NULL);
 
		/* 调用type.__init__(事实上type.__init__只做了些检查，没干别的什么) */
		init_args_tuple = PyTuple_New(1);
		PyTuple_SET_ITEM(init_args_tuple, 0, subclass);
		PyType_Type.tp_init(subclass, init_args_tuple, NULL);
 
		/* 子类初始化 */
		ret = PyType_Ready((PyTypeObject*)subclass);
 
		/* 添加子类到配置字典 */
		dict_setitem_string_object(value, HOOK_OBJECT_STRING, subclass);
	}
 
	return ret;
}

/**
  * @description: 根据方法、函数和变量的配置表创建对应的类实例化对象,
  *			      然后将实例化对象添加到对应的配置表中.
  * @param class 创建hook对象的类
  * @param config_class_dict 要创建的hook对象的配置表
  * @return int
  */
int detect_object_create_hook_objects(PyTypeObject *class, 
								      PyObject *config_classes_dict) {
	Py_ssize_t i = 0;
	PyObject *key, *value;
	PyHookObject *hook_object;
	int ret = 0;

	while (PyDict_Next(config_classes_dict, &i, &key, &value)) {
		DETECT_CONFIG_OBJ_TYPE config_obj_type;

		config_obj_type = PyLong_AsLong(PyDict_GetItemString(value, CONFIG_OBJ_TYPE_STRING));
		if (config_obj_type == DETECT_CONFIG_OBJ_TYPE_CLASS) {
			/* 跳过类 */
			continue;
		}

		/* 创建hook的taint类实例对象 */
		hook_object = (PyHookObject *)class->tp_new(class, NULL, NULL);
		hook_object->config_dict = value;

		/* 添加taint类实例对象到外部输入类配置字典 */
		dict_setitem_string_object(value, HOOK_OBJECT_STRING, (PyObject *)hook_object);
	}

	return ret;
}

/**
* @description: 该函数用于从可调用对象的参数元组和字典中获取优先级最高的object模块中对象
* @param args 位置参数元组
* @param kwargs 关键字参数字典
* @return PyObject* object模块中的对象
*/
PyObject* detect_object_get_highest_priority_item_by_args_and_kwargs(PyObject *args, PyObject *kwargs) {
	PyObject *res = NULL;

	if (args != NULL) {
		Py_ssize_t size = PyTuple_Size(args);
		int index;
		for (index = 0; index < size; index++) {
			PyObject *obj = PyTuple_GetItem(args, index);
			if (detect_object_get_object_type(obj) < detect_object_get_object_type(res)) {
				res = obj;
			}
		}
	}

	if (kwargs != NULL) {
		Py_ssize_t i = 0;
		PyObject *key, *value;

		while (PyDict_Next(kwargs, &i, &key, &value)) {
			if (detect_object_get_object_type(key) < detect_object_get_object_type(res)) {
				res = value;
			}
		
			if (detect_object_get_object_type(value) < detect_object_get_object_type(res)) {
				res = value;
			}
		}
	}

	if (res != NULL) {
		Py_INCREF(res);	  
	}

	return res;
}


/**
* @description: 类的tp_getattro通用函数, __getattr__魔术方法通用实现
* @param obj 对象
* @param name 属性或方法名
* @return PyObject *
*/
PyObject *detect_object_class_getattro(PyObject *obj, PyObject *name) {
	Py_INCREF(obj);

	/* __getattr__方法始终返回对象自身 */
	return obj;
}

/**
 * @description: 类的tp_setattro方法实现, __setattr__魔术方法通用实现
 * @param obj 对象
 * @param name 属性名
 * @param value 值
 * @return int
 */
int detect_object_class_setattro(PyObject *obj, PyObject *name, PyObject *value) {

	/* 对象设置属性的通用方法 */
    //return PyObject_GenericSetAttr(obj, name, value);

	/* 暂时不支持属性设置 */
	return 0;
}

/**
 * @description: 类的tp_call方法实现，__call__魔术方法通用实现
 * @param obj 对象
 * @param name 属性名
 * @param value 值
 * @return PyObject*
 */
PyObject *detect_object_class_call(PyObject *obj, PyObject *args, PyObject *kwargs) {
	PyObject *res;
	PyObject *highest_priority_param = detect_object_get_highest_priority_item_by_args_and_kwargs(args, kwargs);

	if (detect_object_get_object_type(highest_priority_param) < detect_object_get_object_type(obj)) {
		res = highest_priority_param;
	} else {
		res = obj;
	}

	Py_INCREF(res);

    return res;
}

/**
* @description: 类的tp_dealloc通用函数, __del__魔术方法通用实现
* @param self 类实例对象
* @return void
*/
void detect_object_class_dealloc(PyObject *self) {

	Py_TYPE(self)->tp_free(self);
}

/**
* @description: 类的tp_iter通用函数, __iter__魔术方法通用实现
* @param self 类实例对象
* @return PyObject*
*/
PyObject* detect_object_class_iter(PyObject *self) {
	PyHookObject *hook_object = (PyHookObject *)self;

	/* 一次新的迭代，重置对象中的迭代计数 */
	hook_object->iter_count = 0;

	Py_INCREF(self);

	return self;
}

/**
* @description: 类的tp_iternext通用函数, __next__魔术方法通用实现
* @param self 类实例对象
* @return PyObject*
*/
PyObject* detect_object_class_iternext(PyObject *self) {
	PyHookObject *hook_object = (PyHookObject *)self;
	int max_count = 3; // 一次迭代需要返回的最大数量

	if (hook_object->iter_count >= max_count) {
		/* 达到返回的最大数量,这里抛出异常是用来通知外层停止迭代 */
		PyErr_SetString(PyExc_StopIteration, "hook object has reached max iter count");
		return NULL;		
	}

	/* 增加一次迭代计数 */
	hook_object->iter_count++;
	Py_INCREF(self);

	return self;
}

/**
* @description: 类的tp_repr通用函数, __repr__魔术方法通用实现
* @param self 类实例对象
* @return PyObject*
*/
PyObject* detect_object_class_repr(PyObject *self) {
	/* 用于debug模式下的调试输出 */
	if (detect_config_get_runtime_state() == RUN_STATE_ANALYSING &&
		detect_config_get_runtime_is_debug()) {

		return PyUnicode_FromFormat("<%s object at %p>", Py_TYPE(self)->tp_name, self);
	}

	/* 返回自身保证污染链的传播，且一定要增加一个引用计数 */
	Py_INCREF(self);
	return self;
}

/**
* @description: 类的tp_str通用函数, __str__魔术方法通用实现
* @param self 类实例对象
* @return PyObject*
*/
PyObject* detect_object_class_str(PyObject *self) {
	/* 用于debug模式下的调试输出 */
	if (detect_config_get_runtime_state() == RUN_STATE_ANALYSING &&
		detect_config_get_runtime_is_debug()) {

		return PyUnicode_FromFormat("<%s object at %p>", Py_TYPE(self)->tp_name, self);
	}

	/* 当str(obj)这样的函数调用时，会引发异常并被CALL_FUNCTION的opcode中捕捉到，
	 * 然后其中可以将调用返回值置为self 。
	 */
	Py_INCREF(self);
	return self;
}

