create a 'server' and 'client' identity:

```
ziti edge create identity device reflect-server -o reflect-server.jwt
ziti edge create identity device reflect-client -o reflect-client.jwt
```

create a service for use by the reflect client/server

```
ziti edge create service reflectsvc
```

authorize the server to 'bind' the reflectsvc

```
ziti edge create service-policy reflectsvc-bind-policy Bind --identity-roles "@reflect-server" --service-roles "@reflectsvc"
```

authorize the client to 'dial' the reflectsvc

```
ziti edge create service-policy reflectsvc-dial-policy Dial --identity-roles "@reflect-client" --service-roles "@reflectsvc"
```

ensure all routers have access to the reflectsvc

```
ziti edge create service-edge-router-policy all-routers-access-reflectsvc --edge-router-roles "#all" --service-roles "@reflectsvc"
```



