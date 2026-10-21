LIBDIR := lib
CLONE  := https://github.com/martinthomson/i-d-template

ifeq (,$(wildcard $(LIBDIR)/main.mk))
$(shell git clone --depth=1 $(CLONE) $(LIBDIR) >&2)
endif

include $(LIBDIR)/main.mk
