#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// ----- Bstring: growable string declarations ----- //

struct Bstring {
  char *data;
  size_t length;
  size_t capacity;
};

#define BSTRING_INIT_CAPACITY 16

struct Bstring *bstring_init(size_t capacity, const char *const s);
bool bstring_append(struct Bstring *self, const char *const s);
void bstring_free(struct Bstring *self);

// ----- HTTP server related declarations ----- //

enum HttpMethodTyp {
  HTTP_UNKNOWN = 0,
  HTTP_GET,
  HTTP_POST,
  HTTP_PUT,
  HTTP_PATCH,
  HTTP_DELETE,
};

struct HttpMethod {
  const char *const str;
  enum HttpMethodTyp typ;
};

const char HTTP_VERSION[] = "HTTP/1.1";

const char *const STR_HTTP_GET = "GET";
const char *const STR_HTTP_POST = "POST";
const char *const STR_HTTP_PUT = "PUT";
const char *const STR_HTTP_PATCH = "PATCH";
const char *const STR_HTTP_DELETE = "DELETE";

struct HttpMethod KNOWN_HTTP_METHODS[] = {
    {.str = STR_HTTP_GET, .typ = HTTP_GET},
    {.str = STR_HTTP_POST, .typ = HTTP_POST},
    {.str = STR_HTTP_PUT, .typ = HTTP_PUT},
    {.str = STR_HTTP_PATCH, .typ = HTTP_PATCH},
    {.str = STR_HTTP_DELETE, .typ = HTTP_DELETE},
};

size_t KNOWN_HTTP_METHODS_LEN =
    sizeof(KNOWN_HTTP_METHODS) / sizeof(KNOWN_HTTP_METHODS[0]);

#define BUFFER_SIZE 1024
#define MAX_HEADERS 128

struct HttpHeader {
  char *key;
  char *value;
};

struct HttpRequest {
  enum HttpMethodTyp method;
  char *path;

  // headers
  struct HttpHeader *headers;
  size_t headers_len;

  // the request buffer
  char *_buffer;
  size_t _buffer_len;

  struct Bstring *body;
};

void handle_connection(int conn_fd);

int server_fd = -1;
struct sockaddr_in client_addr;
socklen_t client_addr_len = sizeof(client_addr);

struct Bstring *filename = NULL;

int main(int argc, char **argv) {
  // set base directory of public files (defaults to public)
  if (argc > 2) {
    filename = bstring_init(0, argv[2]);
    if (argv[2][strlen(argv[2]) - 1] != '/') {
      bstring_append(filename, "/");
    }
  } else {
    filename = bstring_init(0, "./public/");
  }

  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("error: Socket creation failed: %s...\n", strerror(errno));
    goto cleanup;
  }

  // lose the "Address already in use" error message. why this happens
  // in the first place? well even after the server is closed, the port
  // will still be hanging around for a while, and if you try to restart
  // the server, you'll get an "Address already in use" error message
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("error: SO_REUSEADDR failed: %s \n", strerror(errno));
    goto cleanup;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(4221),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("error: Bind failed: %s \n", strerror(errno));
    goto cleanup;
  }

  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    printf("error: Listen failed: %s \n", strerror(errno));
    goto cleanup;
  }

  printf("Waiting for a client to connect...\n");

  while (true) {
    int conn_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (conn_fd == -1) {
      printf("error: Accept failed: %s \n", strerror(errno));
      continue;
    }

    handle_connection(conn_fd);
  }

cleanup:
  if (server_fd != -1) {
    close(server_fd);
  }

  if (filename != NULL) {
    bstring_free(filename);
  }

  return 0;
}

char *http_get_header(struct HttpRequest *self, char *header) {
  assert(self != NULL);
  assert(header != NULL);

  for (size_t i = 0; i < self->headers_len; ++i) {
    if (strcasecmp(header, self->headers[i].key) == 0) {
      return self->headers[i].value;
    }
  }

  return NULL;
}

void *_handle_connection(void *conn_fd_ptr) {
  assert(conn_fd_ptr != NULL);

  int conn_fd = *(int *)conn_fd_ptr;

  printf("processing connection with fd %d\n", conn_fd);

  // read data from the client
  struct HttpRequest req = {0};
  req._buffer = malloc(BUFFER_SIZE);

  FILE *fp = NULL;
  size_t orig_filename_len = filename->length;

  if (req._buffer == NULL) {
    printf("error: Failed to allocate memory\n");
    goto cleanup;
  }

  ssize_t bytes_read = recv(conn_fd, req._buffer, BUFFER_SIZE - 1, 0);
  if (bytes_read == -1) {
    printf("error: Recv failed: %s \n", strerror(errno));
    goto cleanup;
  } else if (bytes_read == 0) {
    printf("error: Recv: connection closed by client\n");
    goto cleanup;
  }

  // null-terminate _buffer
  req._buffer[bytes_read] = '\0';

  req._buffer_len = (size_t)bytes_read;

  char *parse_buffer = req._buffer;

  // parse method & store it to req
  char *method = strsep(&parse_buffer, " ");
  for (size_t i = 0; i < KNOWN_HTTP_METHODS_LEN; ++i) {
    if (strcmp(method, KNOWN_HTTP_METHODS[i].str) == 0) {
      req.method = KNOWN_HTTP_METHODS[i].typ;

      break;
    }
  }

  // unknowm method
  if (req.method == HTTP_UNKNOWN) {
    printf("error(parse): unknown method %s\n", method);
    goto cleanup;
  }

  // parse path & store it to req
  req.path = strsep(&parse_buffer, " ");

  // parse http version
  strsep(&parse_buffer, "\r");
  // char *http_version = strsep(&parse_buffer, "\r");

  // the \r was consumed but the \n is still remaining so consume it
  parse_buffer++;

  // parse headers & store it to req
  req.headers = malloc(sizeof(struct HttpHeader) * MAX_HEADERS);
  req.headers_len = 0;

  for (size_t i = 0; i < MAX_HEADERS; ++i) {
    char *header_line = strsep(&parse_buffer, "\r");

    parse_buffer++; // consume \n

    // if the line was just "\r\n" i.e the end of headers section
    if (header_line[0] == '\0') {
      break;
    }

    char *key = strsep(&header_line, ":");
    header_line++; // consume the space
    char *value = strsep(&header_line, "\0");

    req.headers[i].key = key;
    req.headers[i].value = value;

    ++req.headers_len;
  }

  // get content length and parse request body
  size_t content_length = 0;
  char *content_length_header = http_get_header(&req, "content-length");
  if (content_length_header != NULL) {
    errno = 0;
    size_t result = strtoul(content_length_header, NULL, 10);
    // store result to content_length if there was no error
    if (errno == 0) {
      content_length = result;
    }
  }

  if (content_length > 0) {
    req.body = bstring_init(content_length + 1, NULL);
    bstring_append(req.body, parse_buffer);

    // content lenth mismatch
    if (req.body->length != content_length) {
    }
  }

  // send response
  int bytes_sent = -1;
  if (strcmp(req.path, "/") == 0) {
    const char res[] = "HTTP/1.1 200 OK\r\n\r\n";
    bytes_sent = send(conn_fd, res, sizeof(res) - 1, 0);
  } else if (strcmp(req.path, "/user-agent") == 0) {
    char *s = http_get_header(&req, "user-agent");
    if (s == NULL) {
      s = "NULL";
    }

    size_t slen = strlen(s);

    char *res = malloc(BUFFER_SIZE);
    sprintf(res,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length:%zu\r\n\r\n"
            "%s",
            slen, s);

    bytes_sent = send(conn_fd, res, strlen(res), 0);
    free(res);
  } else if (strncmp(req.path, "/echo/", 6) == 0) {
    char *s = req.path + 6;
    size_t slen = strlen(s);

    char *res = malloc(BUFFER_SIZE);
    sprintf(res,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length:%zu\r\n\r\n"
            "%s",
            slen, s);

    bytes_sent = send(conn_fd, res, strlen(res), 0);
    free(res);
  } else if (req.method == HTTP_GET && strncmp(req.path, "/files/", 7) == 0) {
    bstring_append(filename, req.path + 7);

    // open the file
    errno = 0;
    fp = fopen(filename->data, "r");
    if (fp == NULL && errno != ENOENT) {
      perror("error: fopen()");
      goto cleanup;
    }

    struct Bstring *res = bstring_init(0, HTTP_VERSION);

    // handle non-existant file
    if (errno == ENOENT) {
      bstring_append(res, " 404 Not Found\r\n\r\n");
      bytes_sent = send(conn_fd, res->data, res->length, 0);
      goto cleanup;
    }

    // go to the end of file
    if (fseek(fp, 0, SEEK_END) != 0) {
      perror("error: fseek()");
      goto cleanup;
    }

    // get file size
    long file_size = ftell(fp);
    if (file_size < 0) {
      perror("error: fseek()");
      goto cleanup;
    }

    // go back to the beginning of file
    errno = 0;
    rewind(fp);
    if (errno != 0) {
      perror("error: rewind()");
      goto cleanup;
    }

    char file_size_str[sizeof(file_size) + 1];
    sprintf(file_size_str, "%ld", file_size);

    bstring_append(res, " 200 OK\r\n");
    bstring_append(res, "Content-Type: application/octet-stream\r\n");
    bstring_append(res, "Content-Length: ");
    bstring_append(res, file_size_str);
    bstring_append(res, "\r\n\r\n");

    bytes_sent = send(conn_fd, res->data, res->length, 0);
    bstring_free(res);

    char buffer[BUFFER_SIZE];

    while (file_size > 0) {
      long bytes_to_read = file_size > BUFFER_SIZE ? BUFFER_SIZE : file_size;
      size_t bytes_read = fread(buffer, bytes_to_read, 1, fp);

      // check if bytes_read is less than expected because of error
      if (bytes_read < bytes_to_read && ferror(fp)) {
        puts("error: fread()");
        goto cleanup;
      }

      bytes_sent = send(conn_fd, buffer, bytes_to_read, 0);
      file_size -= bytes_to_read;
    }

  } else if (req.method == HTTP_POST && strncmp(req.path, "/files/", 7) == 0) {
    bstring_append(filename, req.path + 7);

    // open the file in read mode to check whether it exists or not
    errno = 0;
    fp = fopen(filename->data, "r");
    if (fp != NULL) {
      // file already exists
      const char res[] = "HTTP/1.1 409 Conflict\r\n\r\n";
      bytes_sent = send(conn_fd, res, sizeof(res) - 1, 0);
      goto cleanup;
    }

    // open the file for writing now
    errno = 0;
    fp = fopen(filename->data, "w");
    if (fp == NULL) {
      perror("error: fopen()");
      goto cleanup;
    }

    size_t num_chunks = req.body->length / BUFFER_SIZE;
    if (num_chunks > 0) {
      fwrite(req.body->data, BUFFER_SIZE, num_chunks, fp);
    }

    size_t remaining_bytes = req.body->length % BUFFER_SIZE;
    if (remaining_bytes > 0) {
      fwrite(&req.body->data[req.body->length - remaining_bytes],
             remaining_bytes, 1, fp);
    }

    const char res[] = "HTTP/1.1 201 Created\r\n\r\n";
    bytes_sent = send(conn_fd, res, sizeof(res) - 1, 0);
  } else {
    const char res[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    bytes_sent = send(conn_fd, res, sizeof(res) - 1, 0);
  }

  if (bytes_sent == -1) {
    perror("error: send()");
  }

cleanup:
  free(conn_fd_ptr);
  free(req._buffer);
  free(req.headers);
  if (req.body != NULL) {
    bstring_free(req.body);
  }

  close(conn_fd);

  if (fp != NULL) {
    fclose(fp);
  }

  filename->length = orig_filename_len;
  filename->data[orig_filename_len] = '\0';

  return NULL;
}

void handle_connection(int conn_fd) {
  pthread_t new_thread;
  int *conn_fd_ptr = malloc(sizeof(int));
  if (conn_fd_ptr == NULL) {
    printf("error: handle_connection(): Failed to allocate memory for "
           "conn_fd_ptr");
    return;
  }

  *conn_fd_ptr = conn_fd;
  pthread_create(&new_thread, NULL, _handle_connection, conn_fd_ptr);
}

/**
 * initializes a new Bstring. returns `NULL` if memory allocation fails.
 *
 * @param capacity the initial capacity of the vector. if 0, it will be set
 * to a default value.
 * @param s inital value. it must be null terminated. pass `NULL` for no
 * initial value.
 */
struct Bstring *bstring_init(size_t capacity, const char *const s) {
  struct Bstring *bstr = malloc(sizeof(struct Bstring));
  if (bstr == NULL) {
    return NULL;
  }

  if (capacity == 0) {
    capacity = BSTRING_INIT_CAPACITY;
  }

  const size_t slen = (s == NULL) ? 0 : strlen(s);
  if (slen >= capacity) {
    capacity = slen + 1; // +1 for null terminator
  }

  bstr->data = malloc(sizeof(char) * capacity);
  if (bstr->data == NULL) {
    free(bstr);
    return NULL;
  }

  // copy if not NULL
  if (s != NULL) {
    memcpy(bstr->data, s, slen);
  }

  bstr->capacity = capacity;
  bstr->length = slen;
  bstr->data[slen] = '\0';

  return bstr;
}

/**
 * appends the given C string at the end of given bstring
 *
 * @param self the Bstring to append the C string to
 * @param the NULL-terminated C string to be appended
 */
bool bstring_append(struct Bstring *self, const char *const s) {
  assert(self != NULL);
  assert(s != NULL);

  const size_t slen = strlen(s);
  const size_t new_len = self->length + slen;
  if (new_len >= self->capacity) {
    // try doubling the current capacity
    size_t new_cap = self->capacity * 2;

    // check if it's enough
    if (new_len >= new_cap) {
      new_cap = new_len + 1; // +1 for null terminator
    }

    char *new_data = realloc(self->data, new_cap);
    if (new_data == NULL) {
      return false;
    }

    self->data = new_data;
    self->capacity = new_cap;
  }

  memcpy(&self->data[self->length], s, slen); // append
  self->length = new_len;                     // set new length
  self->data[new_len] = '\0';                 // null terminate

  return true;
}

void bstring_free(struct Bstring *self) {
  assert(self != NULL);

  free(self->data);
  free(self);
}
