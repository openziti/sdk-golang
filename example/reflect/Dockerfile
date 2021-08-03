FROM golang
RUN go get -u github.com/openziti/sdk-golang/example/reflect
ENV GO111MODULE=on
ENV GOFLAGS=-mod=vendor
ENV APP_USER=appuser
ENV APP_GROUP=appgroup
ENV APP_HOME=/app
ARG GROUP_ID=1000
ARG USER_ID=1000
RUN groupadd --gid $GROUP_ID $APP_GROUP && useradd -m -l --uid $USER_ID --gid $GROUP_ID $APP_USER
RUN mkdir -p $APP_HOME
RUN chown -R $APP_USER:$APP_GROUP $APP_HOME
RUN chmod -R 0777 $APP_HOME
USER $APP_USER
WORKDIR $APP_HOME
VOLUME /identity
EXPOSE 8010
CMD reflect server --verbose --identity=/identity/${IDENTITY_FILE} --serviceName="${SERVICE_NAME}"
