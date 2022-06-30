SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))

all: pam_rc2022.so

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) -I$(SRC) -c $< -o $@

pam_rc2022.so: pam_rc2022.o
	$(CC) -fPIC -DPIC -shared -rdynamic $< -o $@
