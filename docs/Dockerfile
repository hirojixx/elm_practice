FROM debian:11.0-slim

RUN apt update
RUN apt-get install -y wget
RUN wget -O - 'https://github.com/elm/compiler/releases/download/0.19.1/binary-for-linux-64-bit.gz' \
    | gunzip -c >/usr/local/bin/elm
RUN chmod +x /usr/local/bin/elm
RUN apt-get install -y nodejs

# ENTRYPOINT ["elm"]

# NOTE: you actually do need unsafe perm to install elm packages with npm
# RUN npm install --unsafe-perm -g elm-test@0.19.0-rev6

# NOTE: we need to set HOME, because elm uses $HOME/.elm to save packages.
#       if this doesn't persist between runs, you get CORRUPT BINARY errors.
ENV HOME /code

WORKDIR /code