#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#define NFDS 2

int debug_mode = 1;

typedef void (*received_cb)(void *cbarg, char *line);

struct reader {
    int fd;
    int bufsize;
    int len;
    char *buf;
    received_cb cb;
    void *cbarg;
};

static int reader_init(struct reader *r, int fd, int bufsize, received_cb cb,
                       void *cbarg)
{
    /* TODO: make fd non blocking */

    r->fd = fd;
    r->bufsize = bufsize;
    r->len = 0;
    r->buf = malloc(bufsize);
    if (r->buf == NULL)
        return -1;

    r->buf[r->len] = 0;
    r->cb = cb;
    r->cbarg = cbarg;

    return 0;
}

static void reader_destroy(struct reader *r)
{
    close(r->fd);
    free(r->buf);

    r->fd = -1;
    r->buf = NULL;
}

static void reader_clear(struct reader *r)
{
    r->len = 0;
    r->buf[r->len] = 0;
}

static void reader_shift(struct reader *r, char *partial_line)
{
    assert(partial_line > r->buf && partial_line < r->buf + r->len);

    ssize_t len = r->buf + r->len - partial_line;
    memmove(r->buf, partial_line, len);
    r->len = len;
    r->buf[r->len] = 0;
}

static int reader_read(struct reader *r)
{
    int nread;
    do {
        nread = read(r->fd, r->buf + r->len, r->bufsize - r->len - 1);
    } while (nread == -1 && errno == EINTR);

    if (nread == -1)
        return errno == EAGAIN ? 0 : -1;

    if (nread == 0) {
        errno = ECONNRESET;
        return -1;
    }

    r->len += nread;
    r->buf[r->len] = 0;

    return nread;
}

static void reader_process(struct reader *r)
{
    char *next = r->buf;
    char *line;

    for (;;) {
        line = strsep(&next, "\n");

        if (next == NULL) {

            if (line == r->buf && r->len == r->bufsize - 1) {
                /* Buffer full without newline in sight - drop entire buffer */
                log_error("discarding excessive long line");
                reader_clear(r);
                return;
            }

            if (line == r->buf + r->len) {
                /* No more data to process */
                reader_clear(r);
                return;
            }

            if (line > r->buf) {
                /* Shit partial line to start fo buffer */
                reader_shift(r, line);
                return;
            }

            /* Partial line at start of buffer, wait for more data */
            return;
        }

        r->cb(r->cbarg, line);
    }
}

static void reader_cb(void *ctx, int revents)
{
    struct reader *r = (struct reader *)ctx;

    if (revents & POLLIN) {
        int nread = reader_read(r);
        if (nread < 0) {
            log_error("reader_read: %s", strerror(errno));
            exit(1);
        }

        if (nread)
            reader_process(r);
    }

    if (revents & POLLHUP) {
        log_info("disconnected fd: %d", r->fd);
        exit(1);
    }

    if (revents & POLLERR) {
        log_error("error on fd: %d", r->fd);
        exit(1);
    }
}

double clock_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

#define INTERVAL 10.0
#define MIN_TIMEOUT 0.001

struct path {
    TAILQ_ENTRY(path) entries;
    char *path;
    double deadline;
};

static struct path * path_new(char *path)
{
    struct path *p = malloc(sizeof(*p));
    if (p == NULL)
        return NULL;

    p->path = strdup(path);
    if (p->path == NULL)
        goto error;

    p->deadline = clock_time();

    return p;

error:
    free(p);
    errno = ENOMEM;
    return NULL;
}

static void path_free(struct path *p)
{
    if (p == NULL)
        return;
    free(p->path);
    free(p);
}

struct checker {
    TAILQ_HEAD(pathhead, path) paths;
    int paths_count;
};

static int checker_init(struct checker *c)
{
    TAILQ_INIT(&c->paths);
    c->paths_count = 0;
    return 0;
}

static void checker_add_path(struct checker *c, char *path)
{
    log_info("start checking path '%s'", path);

    struct path *p;

    TAILQ_FOREACH(p, &c->paths, entries) {
        if (strcmp(p->path, path) == 0) {
            log_error("already checking path '%s'", path);
            return;
        }
    }

    p = path_new(path);
    if (p == NULL) {
        log_error("path_new: %s", strerror(errno));
        return;
    }

    /* Run on the next loop cycle */
    TAILQ_INSERT_HEAD(&c->paths, p, entries);

    /* Ensure paths are sorted by deadline */
    struct path *next = TAILQ_NEXT(p, entries);
    if (next && next->deadline < p->deadline)
        p->deadline = next->deadline;

    c->paths_count++;
    log_debug("checking %d paths", c->paths_count);
}

static void checker_remove_path(struct checker *c, char *path)
{
    struct path *p;

    log_info("stop checking path '%s'", path);

    TAILQ_FOREACH(p, &c->paths, entries) {
        if (strcmp(p->path, path) == 0) {
            TAILQ_REMOVE(&c->paths, p, entries);
            path_free(p);
            p = NULL;
            c->paths_count--;
            log_debug("checking %d paths", c->paths_count);
            assert(c->paths_count >= 0 && "negative number of paths");
            return;
        }
    }

    log_debug("not checking '%s'", path);
}

static double checker_deadline(struct checker *c)
{
    struct path *p = TAILQ_FIRST(&c->paths);
    if (p == NULL)
        return clock_time() + INTERVAL;
    return p->deadline;
}

static void checker_timeout(struct checker *c, double deadline)
{
    double now = clock_time();
    struct path *p;

    for (;;) {
        p = TAILQ_FIRST(&c->paths);
        if (p == NULL)
            return;

        if (p->deadline > deadline)
            return;

        TAILQ_REMOVE(&c->paths, p, entries);

        log_debug("checking path '%s' (delay=%f)", p->path, now - p->deadline);

        p->deadline += INTERVAL;

        TAILQ_INSERT_TAIL(&c->paths, p, entries);
    }
}

static int split(char *cmd, char *args[], int n)
{
    char *next = cmd;
    int i;
    for (i = 0; i < n && next != NULL; i++) {
        args[i] = strsep(&next, " ");
        log_debug("args[%d]='%s'", i, args[i]);
    }
    return i;
}

#define MAX_CMD_ARGS 2

static void command_cb(void *cbarg, char *line)
{
    struct checker *c = (struct checker *)cbarg;
    char *argv[MAX_CMD_ARGS] = {0};

    split(line, argv, MAX_CMD_ARGS);

    char *cmd = argv[0];
    if (cmd == NULL) {
        log_error("empty command");
        return;
    }

    if (strcmp(cmd, "start") == 0) {
        char *path = argv[1];
        if (path == NULL) {
            log_error("path required");
            return;
        }
        checker_add_path(c, path);
    } else if (strcmp(cmd, "stop") == 0) {
        char *path = argv[1];
        if (path == NULL) {
            log_error("path required");
            return;
        }

        checker_remove_path(c, path);
    } else {
        log_error("invalid command: '%s'", cmd);
        return;
    }
}

static int set_nonblocking(int fd)
{
    int flags;
    int err;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return -1;

    err = fcntl(fd, F_SETFL, flags| O_NONBLOCK);
    if (err == -1)
        return -1;

    return 0;
}

struct callback {
    void (*cb)(void *ctx, int revents);
    void *ctx;
};

int main()
{
    struct reader reader;
    struct checker checker;
    struct callback cbs[1];
    struct pollfd fds[1];
    int err;
    int ready;
    double now;
    double deadline;
    long timeout_msec;

    err = set_nonblocking(STDIN_FILENO);
    assert(err == 0 && "cannot set fd to non-blocking");

    err = reader_init(&reader, STDIN_FILENO, 4096, command_cb, &checker);
    assert(err == 0 && "reader_init failed");

    err = checker_init(&checker);
    assert(err == 0 && "checker_init failed");

    cbs[0].cb = reader_cb;
    cbs[0].ctx = &reader;
    fds[0].fd = reader.fd;
    fds[0].events = POLLIN;

    for (;;) {
        now = clock_time();
        deadline = checker_deadline(&checker);
        timeout_msec = (deadline - now) * 1000;

        if (timeout_msec < 0)
            timeout_msec = 0;

        log_debug("waiting for events %ld msec", timeout_msec);
        ready = poll(fds, 1, timeout_msec);

        if (ready == -1) {
            if (errno != EINTR)
                log_error("poll: %s", strerror(errno));
        }

        now = clock_time();
        if (now > deadline - MIN_TIMEOUT)
            checker_timeout(&checker, deadline);

        if (ready > 0) {
            for (int i = 0; i < 1; i++) {
                if (fds[i].revents)
                    cbs[i].cb(cbs[i].ctx, fds[i].revents);
            }
        }
    }

    reader_destroy(&reader);

    return 0;
}
