# Accepted: the stock nginx entrypoint starts as root to bind :80 and read the
# config, then drops its worker processes to the unprivileged `nginx` user
# (`user nginx;` is the image default). Trivy's DS-0002 only looks for a USER
# instruction and cannot see that hand-off.
#
# Scope of the acceptance: this image serves static files for local
# development. It is not deployed by terraform/ (no ECS task, service or task
# definition references it) and impala-ui/docker-compose.yml does not build it
# — compose runs the upstream nginx image with the html/ and nginx.conf bind
# mounts instead.
#
# The real fix, if this image is ever deployed: switch to
# nginxinc/nginx-unprivileged, move `listen 80` to `listen 8080` in nginx.conf
# and re-map the published port. That is a coordinated change to a file compose
# shares, so it belongs with the deployment work rather than with a scanner
# suppression.
#
# The suppression itself lives in the repo-root .trivyignore.yaml, not here: DS-0002
# is a whole-file finding that trivy reports with no line number, so an inline
# `#trivy:ignore:` marker (the convention used in terraform/*.tf) has nothing to
# attach to and is silently ineffective.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /usr/share/nginx/html/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
