#ifndef DETECT_OBJECT_UNDEF_CLASS_H
#define DETECT_OBJECT_UNDEF_CLASS_H

/* undefined类名称 */
#define UNDEF_CLASS_PREFIX "undefined_class"

/* undefined类 */
extern PyTypeObject PyUndef_Type;

/* undefined类实例对象定义 */
typedef struct {
    PyObject_HEAD
} PyUndefObject;

extern int detect_object_undef_class_init();

#endif

