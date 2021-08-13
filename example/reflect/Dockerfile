FROM golang
#RUN go get -u github.com/openziti/sdk-golang/example/reflect
#RUN go get -u github.com/qrkourier/sdk-golang/example/reflect@ad9ec0f9d9820098bba0e9e11d6295e9d62b41d1
ENV GO111MODULE=on
ENV GOFLAGS=-mod=vendor
ENV APP_USER=appuser
ENV APP_GROUP=appgroup
ENV APP_HOME=/app
ARG GROUP_ID=1000
ARG USER_ID=1000
RUN groupadd --gid $GROUP_ID $APP_GROUP && useradd -m -l --uid $USER_ID --gid $GROUP_ID $APP_USER
RUN mkdir $APP_HOME
RUN chown -R $APP_USER:$APP_GROUP $APP_HOME
RUN chmod -R 0777 $APP_HOME
VOLUME $APP_HOME
WORKDIR $APP_HOME
#RUN go build
USER $APP_USER
EXPOSE 8010
CMD ls -lAh ${APP_HOME}/; ./reflect server --verbose --identity=${APP_HOME}/${IDENTITY_FILE} --serviceName="${SERVICE_NAME}"
