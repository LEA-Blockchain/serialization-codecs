CC = clang

CFLAGS = -Os

WASM_FLAGS = --target=wasm32 -nostdlib -ffreestanding -Wl,--no-entry

WASM_DEFINES = -DLEA_ENV

WASM_VM_EXTRA_FLAGS = -mnontrapping-fptoint -mbulk-memory -msign-ext -msimd128 -mtail-call -mreference-types -matomics -mmultivalue -Xclang -target-abi -Xclang experimental-mv

MVP_CFLAGS = $(shell pkg-config --cflags stdlea-mvp)
MVP_LIBS = $(shell pkg-config --libs stdlea-mvp)
VM_CFLAGS = $(shell pkg-config --cflags stdlea-vm)
VM_LIBS = $(shell pkg-config --libs stdlea-vm)
TEST_CFLAGS = $(shell pkg-config --cflags stdlea)
TEST_LIBS = $(shell pkg-config --libs stdlea)

MVP_TARGET = cte.mvp.wasm
VM_TARGET = cte.vm.wasm
TEST_TARGET = test

CTE_CORE_SRC = cte_core.c cte_pklist.c cte_siglist.c cte_ixdata.c cte_command.c
TEST_SRC = test.c

.PHONY: all clean mvp vm test_target

all: $(MVP_TARGET) $(VM_TARGET) $(TEST_TARGET)

$(MVP_TARGET): $(CTE_CORE_SRC)
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(WASM_DEFINES) \
	$(MVP_CFLAGS) \
	$(CTE_CORE_SRC) \
	$(MVP_LIBS) \
	-o $@

$(VM_TARGET): $(CTE_CORE_SRC)
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(WASM_VM_EXTRA_FLAGS) $(WASM_DEFINES) \
	$(VM_CFLAGS) \
	$(CTE_CORE_SRC) \
	$(VM_LIBS) \
	-o $@

$(TEST_TARGET): $(TEST_SRC) $(CTE_CORE_SRC)
	$(CC) $(CFLAGS) \
	$(TEST_CFLAGS) \
	$(TEST_SRC) $(CTE_CORE_SRC) \
	$(TEST_LIBS) \
	-o $@

mvp: $(MVP_TARGET)

vm: $(VM_TARGET)

test_target: $(TEST_TARGET)

clean:
	rm -f $(MVP_TARGET) $(VM_TARGET) $(TEST_TARGET)