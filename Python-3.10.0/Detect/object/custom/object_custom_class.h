#ifndef DETECT_OBJECT_CUSTOM_CLASS_H
#define DETECT_OBJECT_CUSTOM_CLASS_H

#include "Detect/object/object_common.h"
#include "Detect/configs/config.h"

/* custom类及子类的名称前缀 */
#define CUSTOM_CLASS_PREFIX "custom_class"

/* custom类 */
extern PyTypeObject PyCustom_Type;

/* taint类实例对象定义 */
typedef struct {
    HOOK_OBJECT_HEAD
} PyCustomObject;

extern int detect_object_custom_class_init();

#endif


