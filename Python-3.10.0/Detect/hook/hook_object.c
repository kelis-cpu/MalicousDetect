/*
 * @Description: 类、方法、函数和变量的hook
 */

#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "Detect/configs/config.h"
#include "Detect/object/object.h"
#include "Detect/utils/module.h"
#include "Detect/utils/dict.h"

 /**
  * @description: 根据类、函数和变量配置字典，替换指定的对象为hook对象
  * @param module_dict 指定对象对应的模块
  * @param config_dict 指定对象对应的配置字典
  * @param dict_key 配置字典的key
  * @return int
  */
 static int detect_hook_replace_class_func_var(PyObject *module_dict, 
													 PyObject *config_dict, 
													 const char* dict_key) {
	 PyObject *obj_name;
	 PyObject *hook_object, *original_hooked_obj;
	 DETECT_CONFIG_OBJ_TYPE obj_type;
 
	 obj_type = PyLong_AsLong(PyDict_GetItemString(config_dict, CONFIG_OBJ_TYPE_STRING));
	 obj_name = PyDict_GetItemString(config_dict, dict_key);
	 hook_object = PyDict_GetItemString(config_dict, HOOK_OBJECT_STRING);

	 original_hooked_obj = PyDict_GetItem(module_dict, obj_name);
	 if (original_hooked_obj == NULL) {
		/* 模块不存在时，原始对象会为null */
	 	original_hooked_obj = Py_None;
	 }
	 
	 /* 获取原始的待hook的对象，并将其记录到hook对象的属性中 */
	 if (obj_type == DETECT_CONFIG_OBJ_TYPE_CLASS) {
		 /* taint子类有__dict__属性，因此可以在其上直接设置属性 */
		 PyObject_SetAttrString(hook_object, ORIGINAL_HOOKED_OBJ_STRING, 
							 original_hooked_obj);
	 } else {
		 /* 其他三种外部输入的hook对象为taint类实例化对象，该对象没有__dict__属性 */
		 ((PyHookObject*)hook_object)->original_hooked_obj = original_hooked_obj;
	 }
 
	 /* 替换原始外部输入类对象为taint子类 */
	 PyDict_SetItem(module_dict, obj_name, hook_object);
 
	 return 0;
 }
 
 /**
  * @description: 根据外部输入方法配置字典，替换指定的外部输入方法为hook对象
  * @param module_dict 该外部输入对应的模块
  * @param config_dict 该外部输入对应的配置字典
  * @param dict_key 配置字典的key
  * @return int
  */
 static int detect_hook_replace_method(PyObject *module_dict, 
											 PyObject *config_dict) {
	 PyObject *class_name, *method_name;
	 PyObject *class_object, *method_object;
	 PyObject *hook_object;
 
	 class_name  = PyDict_GetItemString(config_dict, CLASS_NAME_STRING);
	 method_name = PyDict_GetItemString(config_dict, METHOD_NAME_STRING);
	 hook_object = PyDict_GetItemString(config_dict, HOOK_OBJECT_STRING);
 
	 /* 获取待hook的类型对象和方法对象 */
	 class_object  = PyDict_GetItem(module_dict, class_name);
	 method_object = PyObject_GetAttr(class_object, method_name);
 
	 /* 记录原始方法对象到hook对象 */
	 ((PyHookObject*)hook_object)->original_hooked_obj = method_object;
 
	 /* 替换方法对象为hook对象 */
	 PyObject_SetAttr(class_object, method_name, hook_object);

	 return 0;													 
 }
 
 /**
  * @description: 根据配置表，替换指定的对象(类、方法、函数和变量)为hook对象
  * @param configs_dict 某一类配置的配置表
  * @return int
  */
 static int detect_hook_replace_object(PyObject *configs_dict) {
	 int ret = 0;
	 Py_ssize_t i = 0;
	 PyObject *key, *value;
	 PyObject *module_dict;
	 DETECT_CONFIG_OBJ_TYPE obj_type;
 
	 while (PyDict_Next(configs_dict, &i, &key, &value)) {
		 module_dict = module_get_module_dict_by_name(PyDict_GetItemString(value, MODULE_NAME_STRING));
		 if (NULL == module_dict) {
			 continue;
		 }
 
		 obj_type = PyLong_AsLong(PyDict_GetItemString(value, CONFIG_OBJ_TYPE_STRING));
		 switch (obj_type) {
		 case DETECT_CONFIG_OBJ_TYPE_CLASS:  // 类的hook
			 ret = detect_hook_replace_class_func_var(module_dict, value, CLASS_NAME_STRING);
			 break;
		 case DETECT_CONFIG_OBJ_TYPE_METHOD: // 方法的hook
			 ret = detect_hook_replace_method(module_dict, value);
			 break;
		 case DETECT_CONFIG_OBJ_TYPE_FUNC:   // 函数的hook
			 ret = detect_hook_replace_class_func_var(module_dict, value, FUNC_NAME_STRING);
			 break;
		 case DETECT_CONFIG_OBJ_TYPE_VAR:    // 变量的hook
			 ret = detect_hook_replace_class_func_var(module_dict, value, VAR_NAME_STRING);
			 break;
		 default:
			 break;
		 }
	 }
 
	 return ret;
 }
 
 /**
  * @description: 根据外部输入配置表，hook对应的对象为taint对象
  * @return int
  */
int detect_hook_hook_object() {
	int ret = 0;

	/* 主要要将方法的hook放在类前，这样类的hook会覆盖这个类中的方法hook */
	ret = detect_hook_replace_object(g_taint_input_method_dict);
	ret = detect_hook_replace_object(g_taint_input_class_dict);
	ret = detect_hook_replace_object(g_taint_input_func_dict);
	ret = detect_hook_replace_object(g_taint_input_var_dict);

	ret = detect_hook_replace_object(g_threat_method_dict);
	ret = detect_hook_replace_object(g_threat_class_dict);
	ret = detect_hook_replace_object(g_threat_func_dict);

	ret = detect_hook_replace_object(g_custom_method_dict);
	ret = detect_hook_replace_object(g_custom_class_dict);
	ret = detect_hook_replace_object(g_custom_func_dict);

	return ret;
 }

