/*
 * Copyright 2016 Nir Soffer <nsoffer@redhat.com>
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>  /* strsep */
#include <unistd.h>  /* read */

#include <ev.h>

#include "reader.h"
#include "log.h"

void reader_init(struct reader *r, int fd, received_cb cb)
{
    r->fd = fd;
    r->cb = cb;
    reader_clear(r);
}

void reader_clear(struct reader *r)
{
    r->end = r->buf;
    *r->end = 0;
}

void reader_shift(struct reader *r, char *partial_line)
{
    assert(partial_line > r->buf && partial_line < r->end);

    ssize_t len = r->end - partial_line;
    memmove(r->buf, partial_line, len);
    r->end = r->buf + len;
    *r->end = 0;
}

ssize_t reader_available(struct reader *r)
{
    return r->buf + sizeof(r->buf) - r->end - 1;
}

int reader_read(struct reader *r)
{
    ssize_t nread;

    do {
        nread = read(r->fd, r->end, reader_available(r));
    } while (nread == -1 && errno == EINTR);

    if (nread == -1) {
        if (errno == EAGAIN)
            return 0;
        return -1;
    }

    if (nread == 0) {
        errno = ECONNRESET;
        return -1;
    }

    r->end += nread;
    *r->end = 0;

    log_debug("read %ld bytes len=%ld", nread, r->end - r->buf);

    return nread;
}

void reader_process(struct reader *r)
{
    char *next = r->buf;
    char *line;

    for (;;) {
        line = strsep(&next, "\n");

        if (next == NULL) {

            if (line == r->buf && reader_available(r) == 0) {
                /* Buffer full without newline in sight - drop entire buffer */
                log_error("discarding excessive long line");
                reader_clear(r);
                /* TODO: send error to caller */
                return;
            }

            if (line == r->end) {
                /* No more data to process */
                log_debug("all data processed");
                reader_clear(r);
                return;
            }

            if (line > r->buf) {
                /* Shit partial line to start fo buffer */
                log_debug("shift partial line: '%s'", line);
                reader_shift(r, line);
                return;
            }

            /* Partial line at start of buffer, wait for more data */
            log_debug("partial data, waiting for more data");
            return;
        }

        r->cb(line);
    }
}

void reader_cb(EV_P_ ev_io *w, int revents)
{
    struct reader *r = (struct reader *)w;
    int nread;

    nread = reader_read(r);
    if (nread == -1) {
        perror("ERROR reader_read");
        ev_break(EV_A_ EVBREAK_ALL);
        return;
    }

    if (nread)
        reader_process(r);
}