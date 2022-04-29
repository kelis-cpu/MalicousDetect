#ifndef DETECT_OBJECT_THREAT_CLASS_H
#define DETECT_OBJECT_THREAT_CLASS_H

#include "Detect/object/object_common.h"
#include "Detect/configs/config.h"

/* threat类及子类的名称前缀 */
#define THREAT_CLASS_PREFIX "threat_class"

/* threat类 */
extern PyTypeObject PyThreat_Type;

/* threat类实例对象定义 */
typedef struct {
    HOOK_OBJECT_HEAD
} PyThreatObject;

extern int detect_object_threat_class_init();

#endif


