#ifndef DETECT_UTILS_MODULE_H
#define DETECT_UTILS_MODULE_H

#define CREATED_BY_DETECT_KEY "created_by_detect"

extern bool module_is_imported_by_name(PyObject *module_name);
extern PyObject *module_get_module_dict_by_name(PyObject *module_name);
extern PyObject *module_import_name(PyThreadState *tstate, PyFrameObject *f,
            PyObject *name, PyObject *fromlist, PyObject *level);
extern PyObject* module_create_module(PyObject *module_name);
extern PyObject* module_get_attr_by_string(PyObject *module_obj, const char *attr_name);
extern PyObject* module_get_attr(PyObject *module_obj, PyObject *attr_name);

#endif

