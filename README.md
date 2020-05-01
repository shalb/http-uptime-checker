# http-uptime-checker
http-uptime-checker for prometheus monitoring

## Info

Use this container to monitor single http endpoin uptime with custom rules.

## build

~~~~
docker login
docker-compose -f docker-compose-build.yml build
docker-compose -f docker-compose-build.yml push
~~~~

## configuration

Customize your configuration via config file entrypoint/entrypoint.py.yml

## run

Use docker-compose.yml to run container with env variables
~~~~
docker-compose up
~~~~

## dependencies if want to run without container

pip3 install --user pyaml prometheus_client

