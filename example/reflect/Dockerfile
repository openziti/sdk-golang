FROM golang
RUN go get -u github.com/qrkourier/sdk-golang/example/reflect@enhance-reflect-example
ENV GO111MODULE=on
ENV GOFLAGS=-mod=vendor
ENV APP_USER=appuser
ENV APP_GROUP=appgroup
ENV APP_HOME=/app
ARG GROUP_ID=1000
ARG USER_ID=1000
RUN groupadd --gid ${GROUP_ID} ${APP_GROUP} && useradd -m -l --uid ${USER_ID} --gid ${GROUP_ID} ${APP_USER}
RUN mkdir ${APP_HOME}
RUN chown -R ${APP_USER}:${APP_GROUP} ${APP_HOME}
RUN chmod -R 0777 ${APP_HOME}
VOLUME ${APP_HOME}
WORKDIR ${APP_DIR}
USER ${APP_USER}
CMD ls -lAh ${APP_DIR}/; reflect server --verbose --identity=${APP_DIR}/${ZITI_SDK_CONFIG} --serviceName="${SERVICE_NAME}"
