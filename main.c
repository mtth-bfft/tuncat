#include <stdio.h>
#define __USE_POSIX
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define STR(x) #x
#define UNUSED(x) (void)(x)

#ifndef DEFAULT_BUFFER_LEN
#define DEFAULT_BUFFER_LEN 65536
#endif

static volatile int interrupt_flag = 0;
static int verbosity = 0;

void print_usage(FILE *f)
{
	fprintf(f, "Usage: tuncat [-i tunX] [-b bufferlen] [-v] [-e] [-f] [-p]\n");
	fprintf(f, "\n");
	fprintf(f, "  -v, --verbose         increase verbosity (can be repeated)\n");
	fprintf(f, "  -i, --interface=tunX  use a (possibly existing) tun interface\n");
	fprintf(f, "  -e, --ethernet        add ethernet headers (tap instead of tun)\n");
	fprintf(f, "  -f, --flags           add flags+protocol preamble (2x2bytes)\n");
	fprintf(f, "  -p, --permanent       keep the device after program exit\n");
	fprintf(f, "  -u, --user=[id|name]  set the device owner (default is euid)\n");
	fprintf(f, "  -g, --group=[id|name] set the device group (default is egid)\n");
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

int get_uid_by_name(const char *name, uid_t *id)
{
	if (name == NULL || id == NULL)
		return EINVAL;
	char *endptr = NULL;
	errno = 0;
	long conv = strtol(name, &endptr, 10);
	if (endptr != NULL && *endptr == '\0' && errno == 0) {
		if (conv < 0 || conv > ((unsigned int)-1)) {
			fprintf(stderr, "Error: invalid user id\n");
			return ERANGE;
		}
		*id = conv;
		return 0;
	}
	struct passwd *pw = getpwnam(name);
	if (pw == NULL) {
		fprintf(stderr, "Error: user not found\n");
		return EINVAL;
	}
	*id = pw->pw_uid;
	return 0;
}

int get_gid_by_name(const char *name, gid_t *id)
{
	if (name == NULL || id == NULL)
		return EINVAL;
	char *endptr = NULL;
	errno = 0;
	long conv = strtol(name, &endptr, 10);
	if (endptr != NULL && *endptr == '\0' && errno == 0) {
		if (conv < 0 || conv > ((unsigned int)-1)) {
			fprintf(stderr, "Error: invalid group id\n");
			return ERANGE;
		}
		*id = conv;
		return 0;
	}
	struct group *gr = getgrnam(name);
	if (gr == NULL) {
		fprintf(stderr, "Error: group not found\n");
		return EINVAL;
	}
	*id = gr->gr_gid;
	return 0;
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

int create_tun(int *tun_fd, char *name, size_t name_buffer_len, int persistent,
	uid_t uid, gid_t gid)
{
	if (tun_fd == NULL)
		return EINVAL;

	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error: could not open tun/tap module interface\n");
		perror("open('/dev/net/tun')");
		return errno;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (name != NULL) {
		if (strlen(name) >= IFNAMSIZ) {
			fprintf(stderr, "Error: interface name too long\n");
			close(fd);
			return ENAMETOOLONG;
		}
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
	}

	int res = ioctl(fd, TUNSETIFF, (void*)&ifr);
	if (res < 0) {
		fprintf(stderr, "Error: cannot communicate with tun/tap module\n");
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return errno;
	}

	int saved_flags = fcntl(fd, F_GETFL);
	if (saved_flags < 0) {
		fprintf(stderr, "Error: unable to get flags from tun fd\n");
		close(fd);
		return errno;
	}
	res = fcntl(fd, F_SETFL, saved_flags | O_NONBLOCK);
	if (res < 0) {
		fprintf(stderr, "Error: unable to make tun fd non-blocking\n");
		close(fd);
		return errno;
	}

	if (persistent) {
		res = ioctl(fd, TUNSETPERSIST, (persistent ? 1 : 0));
		if (res < 0) {
			fprintf(stderr, "Error: unable to make tun persistent\n");
			close(fd);
			return errno;
		}
	}

	if (uid != (uid_t)(-1)) {
		res = ioctl(fd, TUNSETOWNER, uid);
		if (res < 0) {
			fprintf(stderr, "Error: unable to set owner to %ld\n",
				(long)uid);
			perror("ioctl(TUNSETOWNER)");
			close(fd);
			return errno;
		}
	}

	if (gid != (gid_t)(-1)) {
		res = ioctl(fd, TUNSETGROUP, gid);
		if (res < 0) {
			fprintf(stderr, "Error: unable to set group to %ld\n",
				(long)gid);
			perror("ioctl(TUNSETGROUP)");
			close(fd);
			return errno;
		}
	}

	size_t actual_len = strlen(ifr.ifr_name);
	if (name != NULL) {
		if (actual_len >= name_buffer_len) {
			fprintf(stderr, "Error: interface name too long for buffer\n");
			close(fd);
			return 2;
		}
		strncpy(name, ifr.ifr_name, name_buffer_len);
	}

	*tun_fd = fd;
	return 0;
}

int close_tun(int fd)
{
	if (fd <= 0)
		return EINVAL;
	if (close(fd) != 0)
		return errno;
	return 0;
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
		{"user", required_argument, 0, 'u'},
		{"group", required_argument, 0, 'g'},
		{"buffer", required_argument, 0, 'b'},
		{NULL, 0, 0, 0}
	};

	int persistent = 0;
	int buffer_len = DEFAULT_BUFFER_LEN;
	uid_t uid = geteuid();
	gid_t gid = getegid();

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
		case 'u':
			res = get_uid_by_name(optarg, &uid);
			break;
		case 'g':
			res = get_gid_by_name(optarg, &gid);
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
			res = 1;
		}
	} while(res == 0 && chr != -1);

	if (res != 0)
		goto cleanup;

	int tun_fd = 0;
	res = create_tun(&tun_fd, ifr.ifr_name, IFNAMSIZ, persistent, uid, gid);
	if (res != 0)
		goto cleanup;
	fprintf(stderr, "Listening on %s\n", ifr.ifr_name);

cleanup:
	if (tun_fd != 0)
		close_tun(tun_fd);
	return res;
}
