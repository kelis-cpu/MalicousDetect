/*
 * @Description: custom类对象的实例化，这些custom对象作为外部输入方法、函数和变量的hook对象
 */

#include "Python.h"
#include "pycore_interp.h"
#include "pycore_pystate.h"
#include "import.h"
#include "object.h"
#include "Detect/object/object_common.h"
#include "Detect/object/custom/object_custom_class.h"
#include "Detect/utils/dict.h"

/**
  * @description: custom类实例化对象初始化
  * @return void
  */
int detect_object_custom_object_init() {
	int ret = 0;

	/* 根据自定义方法、函数和变量的配置表创建对应的custom类实例化对象 */
	ret = detect_object_create_hook_objects(&PyCustom_Type, g_custom_all_dict);

	return ret;
}



