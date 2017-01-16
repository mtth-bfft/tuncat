#include <stdio.h>
#define __USE_POSIX
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define STR(x) #x
#define UNUSED(x) (void)(x)

#define DEFAULT_BUFFER_LEN 65536

static volatile int interrupt_flag = 0;
static int verbosity = 0;

void print_usage(FILE *f)
{
	fprintf(f, "Usage: tuncat [-i tunX] [-p]\n");
	fprintf(f, "\n");
	fprintf(f, "  -v, --verbose         increase verbosity (can be repeated)\n");
	fprintf(f, "  -i, --interface=tunX  use a (possibly existing) tun interface\n");
	fprintf(f, "  -e, --ethernet        add ethernet headers (tap instead of tun)\n");
	fprintf(f, "  -f, --flags           add flags+protocol preamble (2x2bytes)\n");
	fprintf(f, "  -p, --permanent       keep the device after program exit\n");
	fprintf(f, "  -b, --buffer=bytes    override default " STR(DEFAULT_BUFFER_LEN) "B buffer size\n");
}

void signal_handler(int signum)
{
	UNUSED(signum);
	interrupt_flag = 1;
}

int setup_signal_handlers()
{
	struct sigaction act;
	act.sa_handler = &signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	int res = sigaction(SIGINT, &act, NULL);
	if (res != 0)
		return res;

	res = sigaction(SIGTERM, &act, NULL);
	return res;
}

int infinite_loop(int tun_fd, size_t buffer_len)
{
	fd_set read_set;
	fd_set write_set;
	FD_ZERO(&read_set);
	FD_ZERO(&write_set);
	int res = 0;
	int nfds = tun_fd + 1;
	char *buffer = calloc(buffer_len, 1);
	if (buffer == NULL)
		return ENOMEM;

	while (res == 0) {
		FD_SET(tun_fd, &read_set);
		FD_SET(STDIN_FILENO, &read_set);
		FD_SET(STDOUT_FILENO, &write_set);
		res = select(nfds, &read_set, &write_set, NULL, NULL);
		if (res < 0) {
			if (errno == EINTR) {
				res = 0;
				break;
			}
			perror("select()");
			res = errno;
		}
		if (interrupt_flag != 0) {
			fprintf(stderr, "Received interrupt, exiting\n");
			break;
		}
	}
	return res;
}

int main(int argc, char *argv[])
{
	int res = 0;
	struct option long_options[] = {
		{"verbose", no_argument, 0, 'v'},
		{"interface", required_argument, 0, 'i'},
		{"ethernet", no_argument, 0, 'e'},
		{"flags", no_argument, 0, 'f'},
		{"permanent", no_argument, 0, 'p'},
		{"buffer", required_argument, 0, 'b'},
		{NULL, 0, 0, 0}
	};

	int persistent = 0;
	int buffer_len = DEFAULT_BUFFER_LEN;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_NO_PI;

	int chr = 0, num = 0;
	do {
		chr = getopt_long(argc, argv, "vi:efpb:", long_options, &num);
		switch(chr) {
		case -1:
			break;
		case 'v':
			verbosity++;
			break;
		case 'i':
			if (strlen(optarg) == 0 || strlen(optarg) >= IFNAMSIZ) {
				fprintf(stderr, "Error: invalid interface name\n");
				res = EINVAL;
				break;
			}
			strncpy(ifr.ifr_name, optarg, IFNAMSIZ);
			break;
		case 'e':
			ifr.ifr_flags &= ~IFF_TUN;
			ifr.ifr_flags |= IFF_TAP;
			break;
		case 'f':
			ifr.ifr_flags &= ~IFF_NO_PI;
			break;
		case 'p':
			persistent = 1;
			break;
		case 'b':
			buffer_len = strtol(optarg, NULL, 10);
			if (buffer_len <= 0) {
				fprintf(stderr, "Error: invalid buffer size\n");
				res = EINVAL;
				break;
			}
		default:
			print_usage(stderr);
			break;
		}
	} while(res == 0 && chr != -1);

	return res;
}
