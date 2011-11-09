CFLAGS=-Wall
CC=gcc
OPT=-O2
LIBS = -lccn -lcrypto
INCLUDE = -I/home/paolo/ccn/ccnx/include/
LDFLAGS = -L/home/ccn/ccnx/lib -L/home/paolo/ccn/ccnx/csrc/lib

all: firstauth_cm firstauth_fixture receive_command_symm send_command_symm compute_app_secret_key

firstauth_cm: authentication.o encryption.o toolkit.o firstauth_cm.c
	$(CC) firstauth_cm.c $(CFLAGS) $(LDFLAGS) $(INCLUDE) $(OPT) authentication.o encryption.o toolkit.o $(LIBS) -o firstauth_cm

firstauth_fixture: authentication.o encryption.o toolkit.o firstauth_fixture.c
	$(CC) firstauth_fixture.c $(CFLAGS) $(LDFLAGS) $(INCLUDE) $(OPT) authentication.o encryption.o toolkit.o $(LIBS) -o firstauth_fixture

receive_command_symm: authentication.o receive_command_symm.c
	$(CC) receive_command_symm.c $(CFLAGS) $(LDFLAGS) $(INCLUDE) $(OPT) authentication.o encryption.o toolkit.o $(LIBS) -o receive_command_symm

send_command_symm: authentication.o encryption.o toolkit.o send_command_symm.c
	$(CC) send_command_symm.c $(CFLAGS) $(LDFLAGS) $(INCLUDE) $(OPT) authentication.o encryption.o toolkit.o $(LIBS) -o send_command_symm

compute_app_secret_key: authentication.o encryption.o toolkit.o compute_app_secret_key.c
	$(CC) compute_app_secret_key.c $(CFLAGS) $(LDFLAGS) $(INCLUDE) $(OPT) authentication.o encryption.o toolkit.o $(LIBS) -o compute_app_secret_key

authentication.o: authentication.c
	$(CC)  authentication.c $(LIBS) $(LDFLAGS) $(INCLUDE) $(CFLAGS) $(OPT) -c

encryption.o: encryption.c
	$(CC) encryption.c $(LIBS) $(LDFLAGS) $(INCLUDE) $(CFLAGS) $(OPT) -c

toolkit.o: toolkit.c
	$(CC)  toolkit.c $(LIBS) $(LDFLAGS) $(INCLUDE) $(CFLAGS) $(OPT) -c

encoding.o: encoding.c
	$(CC)  authentication.c $(LIBS) $(LDFLAGS) $(INCLUDE) $(CFLAGS) $(OPT) -c

clean:
	rm -f *o firstauth_cm firstauth_fixture receive_command_symm send_command_symm compute_app_secret_key firstauth_fixture bench
