#ifndef DETECT_OBJECT_TAINT_CLASS_H
#define DETECT_OBJECT_TAINT_CLASS_H

#include "Detect/object/object_common.h"
#include "Detect/configs/config.h"

/* taint类及子类的名称前缀 */
#define TAINT_CLASS_PREFIX "taint_class"

/* taint类 */
extern PyTypeObject PyTaint_Type;

/* taint类实例对象定义 */
typedef struct {
    HOOK_OBJECT_HEAD
} PyTaintObject;

extern int detect_object_taint_class_init();

#endif

