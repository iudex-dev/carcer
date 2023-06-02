FROM silkeh/clang AS build
RUN apt update && apt install libseccomp-dev
WORKDIR /tmp
COPY carcer.c /tmp/
RUN clang -o carcer carcer.c -lseccomp -lpthread -static

FROM alpine:3.18
WORKDIR /iudex
COPY --from=build /tmp/carcer /bin
