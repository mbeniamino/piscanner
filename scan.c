#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>

#define CHECK_SCP_RC(session, scp, rc, msg) \
do { \
    if ((rc) != SSH_OK) { \
        fprintf(stderr, "%s: %s\n", msg, ssh_get_error((session))); \
        ssh_scp_free((scp)); \
        return (rc == SSH_OK); \
    } \
} while(0)

const char *acquire_py =
"import picamera\n"
"import io\n"
"import sys\n"
"import time\n"
"\n"
"offset = 6404096\n"
"n_pix = 5\n"
"if len(sys.argv) > 1:\n"
"        n_pix = int(sys.argv[1])\n"
"\n"
"stream = io.BytesIO()\n"
"with picamera.PiCamera() as camera:\n"
"        time.sleep(2)\n"
"        for i in range(n_pix):\n"
"                camera.capture(stream, format='jpeg', bayer=True)\n"
"                data = stream.getvalue()[-offset:]\n"
"                assert data[:4] == 'BRCM'\n"
"                data = data[32768:]\n"
"                sys.stdout.write(data)\n"
"";

#define PHEIGHT 1944
#define PWIDTH 2592
#define RAW_DATA_WIDTH (PWIDTH*5/4)
#define RAW_WIDTH 3264
#define RAW_HEIGHT 1952
#define PSIZE (PHEIGHT*PWIDTH)

struct scanner {
    int16_t pic[PSIZE];
};

typedef int (*outProcFun)(void*, ssh_channel*);

int echoStdOut(void* context, ssh_channel *channel) {
    int nbytes;
    char buffer[256];
    nbytes = ssh_channel_read(*channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        if (write(1, buffer, nbytes) != (unsigned int)nbytes) {
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(*channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0) {
        return SSH_ERROR;
    }
    return SSH_OK;
}

bool ssh_channel_skip_n(ssh_channel channel, uint32_t count) {
    unsigned char dummy;
    int tot_to_read = count;
    int nbytes = 1;
    while(tot_to_read > 0 && nbytes >= 0) {
        nbytes = ssh_channel_read_timeout(channel, &dummy, 1, 0, -1);
        tot_to_read -= nbytes;
    }
    return nbytes >= 0 && tot_to_read == 0;
}

int acquire(void* context, ssh_channel* channel) {
    int nbytes;
    unsigned char buffer[5];
    int n_pics = 0;
    bool go_on = true;
    struct scanner *s = (struct scanner*)context;
    memset(s->pic, 0, PSIZE);
    ssh_channel_set_blocking(*channel, 1);
    while (go_on) {
        int dest_idx = 0;
        int row = 0;
        while(row < RAW_HEIGHT && go_on) {
            if (row < PHEIGHT) {
                int col = 0;
                while (col < RAW_WIDTH && go_on) {
                    if (col < RAW_DATA_WIDTH) {
                        int to_read = sizeof(buffer);
                        while(to_read > 0) {
                            nbytes = ssh_channel_read_timeout(*channel, &buffer[sizeof(buffer)-to_read], to_read, 0, -1);
                            if(nbytes <= 0) break;
                            to_read -= nbytes;
                            col += nbytes;
                        }
                        if (nbytes < 0) {
                            return SSH_ERROR;
                        } else if (nbytes == 0 && dest_idx > 0) {
                            return SSH_ERROR;
                        } else if (nbytes == 0) {
                            go_on = false;
                            break;
                        }
                        for (int i = 0; i < 4; ++i) {
                            s->pic[dest_idx+i] += (buffer[i] << 2) + ((buffer[4] >> ((3 - i) * 2)) & 0x3);
                        }
                        dest_idx += 4;
                        if (dest_idx == PSIZE) {
                            ++n_pics;
                            printf("Picture %d processed\n", n_pics);
                        }
                    } else {
                        if (!ssh_channel_skip_n(*channel, RAW_WIDTH - RAW_DATA_WIDTH)) return SSH_ERROR;
                        col += RAW_WIDTH - RAW_DATA_WIDTH;
                    }
                }
            } else {
                int trailing_rows = RAW_HEIGHT - PHEIGHT;
                if (!ssh_channel_skip_n(*channel, RAW_WIDTH * trailing_rows)) return SSH_ERROR;
                row += trailing_rows;
            }
            ++row;
        }
    }
    if (n_pics == 0) return SSH_ERROR;
    printf("Acquired and merged %d pictures!\n", n_pics);
    return SSH_OK;
}

ssize_t my_getpass (char **lineptr, size_t *n, FILE *stream) {
    struct termios old, new;
    int nread;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr (fileno (stream), &old) != 0)
        return -1;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0) {
        return -1;
    }

    /* Read the password. */
    nread = getline (lineptr, n, stream);

    /* Restore terminal. */
    (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);

    return nread;
}

ssh_session setup_ssh(const char* host, const uint32_t *port, const char* user, const char* password) {
    int rc;

    ssh_session session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error opening ssh session");
        exit(-1);
    }
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to the server: %s\n",
                ssh_get_error(session));
        exit(-1);
    }
    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }
    return session;
}

int remote_exec(ssh_session session, const char* command, void* context, outProcFun out_processor) {
    ssh_channel channel;
    int rc;
    channel = ssh_channel_new(session);
    if (channel == NULL)
        return SSH_ERROR;
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    rc = out_processor(context, &channel);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_OK;

}

bool scp(ssh_session session, const char* content, const char* dest_dir, const char* dest_name, int mode) {
    ssh_scp scp;
    int rc;

    size_t len = strlen(content);
    scp = ssh_scp_new(session, SSH_SCP_WRITE, dest_dir);
    if (!scp) {
        fprintf(stderr, "Error allocating scp session: %s\n",
            ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    CHECK_SCP_RC(session, scp, rc, "Error initializing scp session");
    rc = ssh_scp_push_file(scp, dest_name, len, mode);
    CHECK_SCP_RC(session, scp, rc, "Error creating remote file");
    ssh_scp_write(scp, content, len);
    CHECK_SCP_RC(session, scp, rc, "Error writing remote file");
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return true;
}

int main(int argc, char* argv[]) {
    struct scanner *s = (struct scanner*)malloc(sizeof(struct scanner));
    if (argc < 2) {
        printf("Usage: %s <user>@<host>\n", argv[0]);
        return 0;
    }
    int url_l = strlen(argv[1]);
    int idx;
    for(idx = url_l - 1; idx >= 0 && argv[1][idx] != '@'; --idx);
    if (idx < 0) {
        printf("Invalid url: %s\n", argv[1]);
        return 1;
    }
    char *host = &argv[1][idx+1];
    char *user = malloc(idx+1);
    strncpy(user, argv[1], idx);
    user[idx] = 0;
    uint32_t port = 22;
    size_t passlen = 0;
    char *password = NULL;
    printf("Enter ssh password: ");
    my_getpass(&password, &passlen, stdin);
    printf("\n");
    passlen = strlen(password);
    if (password[passlen-1] == '\n') password[passlen-1] = 0;
    ssh_session session = setup_ssh(host, &port, user, password);
    if (!scp(session, acquire_py, "/tmp", "acquire.py", 0755)) {
        fprintf(stderr, "Error uploading script to raspberry\n");
        exit(-1);
    }
    free(password);
    free(user);
    remote_exec(session, "python /tmp/acquire.py", s, acquire);
    ssh_free(session);
    free(s);
    return 0;
}
