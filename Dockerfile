from google/dart:2.7

WORKDIR /app

ADD pubspec.* /app/
RUN pub get
ADD . /app
RUN pub get --offline
RUN chmod +x /app/docker-entry.sh

CMD []
ENTRYPOINT ["/app/docker-entry.sh"]