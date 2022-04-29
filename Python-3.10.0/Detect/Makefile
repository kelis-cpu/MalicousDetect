rwildcard = $(foreach d, $(wildcard $1/*), $(call rwildcard,$d,$2) \
						$(filter $2, $d))

# Detect目录下所有.o文件
DETECT_OBJS = $(subst .c,.o, $(call rwildcard, $(srcdir)/Detect, %.c))

# Detect目录下所有.h文件
DETECT_HEADERS = $(call rwildcard, $(srcdir)/Detect, %.h)
