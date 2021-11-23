FROM golang
ENV GO111MODULE=on
# ENV GOFLAGS=-mod=vendor
ENV APP_USER=appuser
ENV APP_GROUP=appgroup
ENV APP_HOME=/app
ENV SERVICE_NAME="reflect"
ENV PROMETHEUS_SERVICE_NAME="metrics"
ENV IDENTITY_FILE="/${APP_HOME}/reflect-server.json"
ARG GROUP_ID=1000
ARG USER_ID=1000
RUN groupadd --gid $GROUP_ID $APP_GROUP && useradd -m -l --uid $USER_ID --gid $GROUP_ID $APP_USER
RUN mkdir -p $APP_HOME
RUN chown -R $APP_USER:$APP_GROUP $APP_HOME
RUN chmod -R 0777 $APP_HOME
USER $APP_USER
WORKDIR $APP_HOME
ADD . $APP_HOME
RUN go mod download
RUN go build -o reflect ./example/reflect
VOLUME /identity
EXPOSE 8010
CMD ./reflect server --verbose --identity=${IDENTITY_FILE} --serviceName="${SERVICE_NAME}" -p "${PROMETHEUS_SERVICE_NAME}"
