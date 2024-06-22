# HTTP Server from Scratch in C

This is a basic multi-threaded HTTP server written in C without any third-party library. The server listens on a port (4221). You can use `curl` to test the server.

I had already added this to my todo listen after I wrote a [TCP Server in C](https://github.com/biraj21/tcp-server) but since [Build your own HTTP server](https://app.codecrafters.io/courses/http-server/overview) at [CodeCrafters](https://codecrafters.io/) was free this month, I built one just a few hours. The code is bad tho. Have to clean it up.

## How to run

1. Clone the repository

2. Compile client and server programs (don't worry, there's a Makefile to do this for you)

   ```bash
   make
   ```

3. Run the server (it will run on port 4221)

   ```bash
   ./bin/server
   ```

4. Use `curl` to test the server.

   ```bash
   curl -v localhost:4221/echo/abc
   ```

5. Ctrl+C to stop the server
