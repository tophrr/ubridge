/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#include "event_loop.h"
#include "ubridge.h"

/* Initialize epoll manager */
int epoll_manager_init(event_loop_t *loop)
{
    if (!loop) {
        return -1;
    }
    
    /* Create epoll instance */
    loop->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epoll_fd < 0) {
        log_event_loop_error("epoll_manager_init", "epoll_create1 failed");
        return -1;
    }
    
    /* Allocate event array */
    loop->events = malloc(sizeof(struct epoll_event) * loop->max_events);
    if (!loop->events) {
        close(loop->epoll_fd);
        log_event_loop_error("epoll_manager_init", "Failed to allocate event array");
        return -1;
    }
    
    if (debug_level > 1) {
        printf("Initialized epoll manager with fd %d, max_events %d\n", 
               loop->epoll_fd, loop->max_events);
    }
    
    return 0;
}

/* Add file descriptor to epoll */
int epoll_manager_add_fd(event_loop_t *loop, int fd, uint32_t events, void *data)
{
    struct epoll_event ev;
    
    if (!loop || fd < 0) {
        return -1;
    }
    
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = data;
    
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        log_event_loop_error("epoll_manager_add_fd", "epoll_ctl ADD failed");
        return -1;
    }
    
    if (debug_level > 2) {
        printf("Added fd %d to epoll with events 0x%x\n", fd, events);
    }
    
    return 0;
}

/* Modify file descriptor in epoll */
int epoll_manager_modify_fd(event_loop_t *loop, int fd, uint32_t events, void *data)
{
    struct epoll_event ev;
    
    if (!loop || fd < 0) {
        return -1;
    }
    
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = data;
    
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        log_event_loop_error("epoll_manager_modify_fd", "epoll_ctl MOD failed");
        return -1;
    }
    
    if (debug_level > 2) {
        printf("Modified fd %d in epoll with events 0x%x\n", fd, events);
    }
    
    return 0;
}

/* Remove file descriptor from epoll */
int epoll_manager_remove_fd(event_loop_t *loop, int fd)
{
    if (!loop || fd < 0) {
        return -1;
    }
    
    if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        /* Don't log error if fd is already closed */
        if (errno != EBADF && errno != ENOENT) {
            log_event_loop_error("epoll_manager_remove_fd", "epoll_ctl DEL failed");
        }
        return -1;
    }
    
    if (debug_level > 2) {
        printf("Removed fd %d from epoll\n", fd);
    }
    
    return 0;
}

/* Wait for events */
int epoll_manager_wait(event_loop_t *loop, int timeout_ms)
{
    struct epoll_event *events;
    int nfds, i;
    event_handler_t *handler;
    event_type_t event_type;
    
    if (!loop || !loop->events) {
        return -1;
    }
    
    events = (struct epoll_event*)loop->events;
    
    /* Wait for events */
    nfds = epoll_wait(loop->epoll_fd, events, loop->max_events, timeout_ms);
    if (nfds < 0) {
        if (errno != EINTR) {
            log_event_loop_error("epoll_manager_wait", "epoll_wait failed");
        }
        return -1;
    }
    
    /* Process events */
    for (i = 0; i < nfds; i++) {
        handler = (event_handler_t*)events[i].data.ptr;
        if (!handler) {
            continue;
        }
        
        /* Determine event type */
        if (events[i].events & (EPOLLERR | EPOLLHUP)) {
            event_type = EVENT_TYPE_ERROR;
            pthread_mutex_lock(&loop->stats_lock);
            loop->stats.error_events++;
            pthread_mutex_unlock(&loop->stats_lock);
        } else if (events[i].events & EPOLLIN) {
            event_type = EVENT_TYPE_READ;
            pthread_mutex_lock(&loop->stats_lock);
            loop->stats.read_events++;
            pthread_mutex_unlock(&loop->stats_lock);
        } else if (events[i].events & EPOLLOUT) {
            event_type = EVENT_TYPE_WRITE;
            pthread_mutex_lock(&loop->stats_lock);
            loop->stats.write_events++;
            pthread_mutex_unlock(&loop->stats_lock);
        } else {
            continue; /* Unknown event */
        }
        
        /* Call event handler */
        if (handler->callback) {
            int result = handler->callback(loop, handler->fd, event_type, handler->data);
            if (result < 0) {
                if (debug_level > 0) {
                    printf("Event handler returned error for fd %d, event %s\n",
                           handler->fd, event_type_to_string(event_type));
                }
            }
        }
    }
    
    return nfds;
}

/* Cleanup epoll manager */
void epoll_manager_cleanup(event_loop_t *loop)
{
    if (!loop) {
        return;
    }
    
    if (loop->epoll_fd >= 0) {
        close(loop->epoll_fd);
        loop->epoll_fd = -1;
    }
    
    if (loop->events) {
        free(loop->events);
        loop->events = NULL;
    }
    
    if (debug_level > 1) {
        printf("Cleaned up epoll manager\n");
    }
}

#endif /* __linux__ */
