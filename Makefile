CC=tcc
CFLAGS=-I. -I/usr/include/python3.9
CLIBS=-lpython3 -lnettle -lolm -lssl -lcrypto
NAME=matrix_session_extract
SRCDIR=src
TESTDIR=test
DEPS=$(SRCDIR)/$(NAME).h
OUTDIR=out
OBJ_LIB=parse.o util.o pbkdf2.o
OBJ_MAIN=$(addprefix $(OUTDIR)/, $(OBJ_LIB) main.o)
OBJ_TEST=$(addprefix $(OUTDIR)/, $(OBJ_LIB) parse_test.o)

$(OUTDIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: $(OUTDIR)/$(NAME)
$(OUTDIR)/$(NAME): $(OBJ_MAIN)
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

$(OUTDIR)/%.o: $(TESTDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OUTDIR)/tests
$(OUTDIR)/tests: $(OBJ_TEST) $(OUTDIR)/parse_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

watch:
	@command -v inotifywait > /dev/null || \
		{ \
			echo "Please install inotifywait"; exit 2; \
		}
	@while true ; do \
		NAME=$$(inotifywait \
			-e create,modify \
			--include '.*\.(c|h)' \
			--format '%w%f' \
			"$(SRCDIR)" "$(TESTDIR)"); \
		if [ "$$(dirname "$$NAME")" = "$(SRCDIR)" ]; then \
			($(MAKE)); \
		else \
			($(MAKE) test); \
		fi; \
	done


