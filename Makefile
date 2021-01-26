CC=tcc
CFLAGS=-I. -I/usr/include/python3.9
CLIBS=-lpython3 -lnettle -lolm -lssl -lcrypto
NAME=matrix_session_extract
SRCDIR=src
DEPS=$(SRCDIR)/$(NAME).h
OUTDIR=out
OBJ=$(addprefix $(OUTDIR)/, parse.o util.o pbkdf2.o main.o)

$(OUTDIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(OUTDIR)/$(NAME): $(OBJ)
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
			"$(SRCDIR)"); \
		export NAME=$$(basename "$${NAME%%.c}"); \
		($(MAKE)); \
	done


