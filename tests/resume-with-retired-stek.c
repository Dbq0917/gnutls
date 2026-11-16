/*
 * Copyright (C) 2026 Free Software Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* This test checks that session tickets encrypted with a retired
 * session ticket encryption key (STEK) are still accepted for
 * resumption, when the server is supplied with a 128-byte key set
 * holding both the current and the retired master key.  This allows
 * applications to rotate the STEK without invalidating outstanding
 * tickets.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
int main(int argc, char **argv)
{
	exit(77);
}
#else

#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <assert.h>
#include "utils.h"
#include "cert-common.h"

#define ROUNDS 5
#define STEK_SIZE 64

/* Round 0: full handshake, ticket0 issued under keys[0].
 * Round 1: server uses (keys[1], retired keys[0]); ticket0 resumes,
 *          ticket1 is issued under keys[1].
 * Round 2: server uses keys[1] only; ticket0 must not resume.
 * Round 3: server uses (keys[2], retired keys[1]); ticket1 resumes.
 * Round 4: server uses (keys[2], retired keys[0]); ticket1 must not
 *          resume.
 */
static const int expect_resumed[ROUNDS] = { 0, 1, 0, 1, 0 };

static void handshake(gnutls_session_t session)
{
	int ret;

	do {
		ret = gnutls_handshake(session);
	} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

	if (ret < 0)
		fail("handshake failed: %s\n", gnutls_strerror(ret));
}

static void close_session(gnutls_session_t session)
{
	int ret;

	do {
		ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
	} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
}

/* Exchange one application data round-trip, so that the client
 * processes any NewSessionTicket message sent by the server after
 * the handshake. */
static void exchange_data(gnutls_session_t session, int server)
{
	char buf[16];
	int ret;

	if (!server) {
		do {
			ret = gnutls_record_send(session, "hello", 5);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("could not send data: %s\n", gnutls_strerror(ret));
	}

	do {
		ret = gnutls_record_recv(session, buf, sizeof(buf));
	} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
	if (ret < 0)
		fail("could not receive data: %s\n", gnutls_strerror(ret));

	if (server) {
		do {
			ret = gnutls_record_send(session, "hello", 5);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("could not send data: %s\n", gnutls_strerror(ret));
	}
}

static gnutls_datum_t make_key(const gnutls_datum_t *current,
			       const gnutls_datum_t *retired)
{
	gnutls_datum_t key = { NULL, 0 };

	key.size = STEK_SIZE;
	if (retired)
		key.size *= 2;

	key.data = gnutls_malloc(key.size);
	if (key.data == NULL)
		fail("could not allocate session ticket key\n");

	memcpy(key.data, current->data, STEK_SIZE);
	if (retired)
		memcpy(key.data + STEK_SIZE, retired->data, STEK_SIZE);

	return key;
}

static void client(int fd, const char *prio)
{
	gnutls_session_t session;
	gnutls_certificate_credentials_t cred = NULL;
	gnutls_datum_t ticket0 = { NULL, 0 };
	gnutls_datum_t ticket1 = { NULL, 0 };
	int ret;
	int i;

	assert(gnutls_certificate_allocate_credentials(&cred) >= 0);

	for (i = 0; i < ROUNDS; i++) {
		gnutls_datum_t *resume_data = NULL;

		if (i == 1 || i == 2)
			resume_data = &ticket0;
		else if (i == 3 || i == 4)
			resume_data = &ticket1;

		assert(gnutls_init(&session, GNUTLS_CLIENT) >= 0);
		assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

		if (resume_data) {
			ret = gnutls_session_set_data(
				session, resume_data->data, resume_data->size);
			if (ret < 0)
				fail("client: could not set session data: %s\n",
				     gnutls_strerror(ret));
		}

		gnutls_transport_set_int(session, fd);
		gnutls_handshake_set_timeout(session, get_timeout());

		handshake(session);

		if (gnutls_session_is_resumed(session) != expect_resumed[i])
			fail("client: round %d: unexpected resumption status\n",
			     i);

		if (i == 0 || i == 1) {
			gnutls_datum_t *data = i == 0 ? &ticket0 : &ticket1;

			exchange_data(session, 0);

			ret = gnutls_session_get_data2(session, data);
			if (ret < 0)
				fail("client: could not get session data: %s\n",
				     gnutls_strerror(ret));
		}

		close_session(session);
		gnutls_deinit(session);
	}

	gnutls_free(ticket0.data);
	gnutls_free(ticket1.data);
	gnutls_certificate_free_credentials(cred);
}

static void server(int fd, const char *prio, const gnutls_datum_t *keys)
{
	gnutls_certificate_credentials_t cred = NULL;
	int ret;
	int i;

	assert(gnutls_certificate_allocate_credentials(&cred) >= 0);
	assert(gnutls_certificate_set_x509_key_mem(cred, &server_cert,
						   &server_key,
						   GNUTLS_X509_FMT_PEM) >= 0);

	for (i = 0; i < ROUNDS; i++) {
		gnutls_session_t session;
		gnutls_datum_t key;

		switch (i) {
		case 0:
			key = make_key(&keys[0], NULL);
			break;
		case 1:
			key = make_key(&keys[1], &keys[0]);
			break;
		case 2:
			key = make_key(&keys[1], NULL);
			break;
		case 3:
			key = make_key(&keys[2], &keys[1]);
			break;
		default:
			key = make_key(&keys[2], &keys[0]);
			break;
		}

		assert(gnutls_init(&session, GNUTLS_SERVER) >= 0);
		assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

		ret = gnutls_session_ticket_enable_server(session, &key);
		gnutls_free(key.data);
		if (ret < 0)
			fail("server: could not enable session tickets: %s\n",
			     gnutls_strerror(ret));

		gnutls_transport_set_int(session, fd);
		gnutls_handshake_set_timeout(session, get_timeout());

		handshake(session);

		if (gnutls_session_is_resumed(session) != expect_resumed[i])
			fail("server: round %d: unexpected resumption status\n",
			     i);

		if (i == 0 || i == 1)
			exchange_data(session, 1);

		close_session(session);
		gnutls_deinit(session);
	}

	gnutls_certificate_free_credentials(cred);
}

static void check_invalid_key_size(void)
{
	gnutls_session_t session;
	gnutls_datum_t key = { NULL, 0 };
	int ret;

	assert(gnutls_init(&session, GNUTLS_SERVER) >= 0);

	key.size = STEK_SIZE + 32;
	key.data = gnutls_malloc(key.size);
	if (key.data == NULL)
		fail("could not allocate session ticket key\n");

	ret = gnutls_session_ticket_enable_server(session, &key);
	if (ret != GNUTLS_E_INVALID_REQUEST)
		fail("server: invalid key size was accepted\n");

	gnutls_free(key.data);
	gnutls_deinit(session);
}

static void run(const char *name, const char *prio, const gnutls_datum_t *keys)
{
	pid_t child;
	int sockets[2];
	int status = 0;

	success("\ntesting %s\n\n", name);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		perror("socketpair");
		fail("socketpair failed\n");
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		fail("fork failed\n");
	}

	if (child == 0) {
		close(sockets[0]);
		client(sockets[1], prio);
		exit(0);
	}

	close(sockets[1]);
	server(sockets[0], prio, keys);
	waitpid(child, &status, 0);
	check_wait_status(status);
}

void doit(void)
{
	gnutls_datum_t keys[3];
	int i;

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	check_invalid_key_size();

	for (i = 0; i < 3; i++)
		assert(gnutls_session_ticket_key_generate(&keys[i]) >= 0);

	run("tls1.3 resumption with retired stek",
	    "NORMAL:-VERS-ALL:+VERS-TLS1.3", keys);

	for (i = 0; i < 3; i++)
		gnutls_free(keys[i].data);
}

#endif
