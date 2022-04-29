#ifndef DETECT_HOOK_OPCODE_MACRO_H
#define DETECT_HOOK_OPCODE_MACRO_H

#define STACK_POINTER (*stack_pointer_addr)

/* 下方的宏从ceval.c中复制而来 */
#define STACK_LEVEL()          ((int)(stack_pointer - f->f_valuestack))
#define EMPTY()                (STACK_LEVEL() == 0)
#define TOP()                  (STACK_POINTER[-1])
#define SECOND()               (STACK_POINTER[-2])
#define THIRD()                (STACK_POINTER[-3])
#define FOURTH()               (STACK_POINTER[-4])
#define PEEK(n)                (STACK_POINTER[-(n)])
#define SET_TOP(v)             (STACK_POINTER[-1] = (v))
#define SET_SECOND(v)          (STACK_POINTER[-2] = (v))
#define SET_THIRD(v)           (STACK_POINTER[-3] = (v))
#define SET_FOURTH(v)          (STACK_POINTER[-4] = (v))
#define BASIC_STACKADJ(n)      (STACK_POINTER += n)
#define BASIC_PUSH(v)          (*STACK_POINTER++ = (v))
#define BASIC_POP()            (*--STACK_POINTER)
#define PUSH(v)                BASIC_PUSH(v)
#define POP()                  BASIC_POP()
#define STACK_GROW(n)          BASIC_STACKADJ(n)
#define STACK_SHRINK(n)        BASIC_STACKADJ(-n)
#define EXT_POP(STACK_POINTER) (*--(STACK_POINTER))
#define GETLOCAL(i)            (fastlocals[i])
#define SETLOCAL(i, value)      do { PyObject *tmp = GETLOCAL(i); \
                                     GETLOCAL(i) = value; \
                                     Py_XDECREF(tmp); } while (0)

/* Tuple access macros */
#ifndef Py_DEBUG
#define GETITEM(v, i) PyTuple_GET_ITEM((PyTupleObject *)(v), (i))
#else
#define GETITEM(v, i) PyTuple_GetItem((v), (i))
#endif

#endif

