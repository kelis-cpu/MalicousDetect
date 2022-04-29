/*
 * @Description: 方法和函数hook主文件
 */
#include <stdbool.h>
#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "Detect/configs/config.h"
#include "Detect/hook/hook_object.h"
#include "Detect/hook/hook_indirect_taint.h"
#include "Detect/object/object.h"
#include "Detect/utils/module.h"
#include "Detect/utils/dict.h"

/**
 * @description: 根据配置表字典，导入未导入的模块
 * @param config_dict 配置表字典
 * @return int
 */
static int detect_hook_import_config_dict_modules(PyObject *config_dict) {
	Py_ssize_t i = 0;
	PyObject *key, *value;
	PyObject *module_name;
	int ret = 0;

	/* 导入配置表的模块 */
    while (PyDict_Next(config_dict, &i, &key, &value)) {
		module_name = PyDict_GetItemString(value, MODULE_NAME_STRING);
			
		if (module_is_imported_by_name(module_name)) {
			continue;
		}

		/* 这里使用__import__函数来执行导入，不会向名称空间中添加名称 */
		if (NULL == PyImport_Import(module_name)) {
			PyObject *new_module_obj_list;
			int index;
		
			/* 如果模块不存在，创建新的模块对象 */			
			new_module_obj_list = module_create_module(module_name);

			/* 向新创建模块的__dict__中添加__getattr__,用来获取不存在的模块属性时返回未定义对象 */
			for (index = 0; index < PyList_Size(new_module_obj_list); index++) {
				PyModule_AddObject(PyList_GetItem(new_module_obj_list, index), 
									"__getattr__", detect_object_undef_object_create());
			}

			/* __import__不存在的模块会抛出异常 */
			PyErr_Clear();
		}
	}

	return ret;
}

/**
 * @description: 根据配置表，导入未导入的模块
 * @return int
 */
static int detect_hook_import_config_modules() {
	int ret = 0;

	/* 导入外部输入配置表的模块 */
	ret = detect_hook_import_config_dict_modules(g_taint_input_all_dict);

	/* 导入威胁配置表的模块 */
	ret = detect_hook_import_config_dict_modules(g_threat_all_dict);

	/* 导入自定义配置表的模块 */
	ret = detect_hook_import_config_dict_modules(g_custom_all_dict);

	return ret;
}

/**
 * @description: hook初始化函数，用来hook内建方法和函数
 * @return void
 */
int detect_hook_init() {
	int ret = 0;

	/* 根据配置表，将未导入的模块在此处一并导入 */
	ret = detect_hook_import_config_modules();

	/* 遍历配置表中所有模块，hook指定的类、方法、函数和变量 */
	ret = detect_hook_hook_object();

	/* 初始化间接污染模块 */
	detect_hook_indirect_taint_init();

	return ret;
}

