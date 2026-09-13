# One Dockerfile, two images.
#
# Both hosts share every project below Api and Engine, so building them separately would restore and
# compile the same code twice. `--target api` and `--target engine` select which entry point ends up in
# the final layer; everything before that is shared and cached.
#
#   docker build --target api    -t sentinel/api:1.0.0    .
#   docker build --target engine -t sentinel/engine:1.0.0 .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore before the source is copied, so a change to a .cs file does not re-download every package.
# Central package management means Directory.Packages.props is part of the restore input.
COPY Directory.Packages.props Sentinel.slnx ./
COPY src/Sentinel.Domain/Sentinel.Domain.csproj                 src/Sentinel.Domain/
COPY src/Sentinel.Application/Sentinel.Application.csproj       src/Sentinel.Application/
COPY src/Sentinel.Infrastructure/Sentinel.Infrastructure.csproj src/Sentinel.Infrastructure/
COPY src/Sentinel.Api/Sentinel.Api.csproj                       src/Sentinel.Api/
COPY src/Sentinel.Engine/Sentinel.Engine.csproj                 src/Sentinel.Engine/

RUN dotnet restore src/Sentinel.Api/Sentinel.Api.csproj \
 && dotnet restore src/Sentinel.Engine/Sentinel.Engine.csproj

COPY src/ src/

# No apphost: the image runs `dotnet Sentinel.Api.dll`, so a native launcher is dead weight.
RUN dotnet publish src/Sentinel.Api/Sentinel.Api.csproj \
      -c Release -o /app/api --no-restore /p:UseAppHost=false \
 && dotnet publish src/Sentinel.Engine/Sentinel.Engine.csproj \
      -c Release -o /app/engine --no-restore /p:UseAppHost=false

# -- what both images have in common -----------------------------------------------------------------

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime

# Non-root, and the same uid in both images so a volume written by one is readable by the other. The
# base image already provides `app` as 64198; naming it here documents what the manifests assert.
USER 64198:64198

ENV DOTNET_RUNNING_IN_CONTAINER=true \
    ASPNETCORE_ENVIRONMENT=Production \
    # Bind to every interface: in a pod the address that matters is the pod's, not localhost.
    ASPNETCORE_URLS=http://0.0.0.0:8080 \
    # Off, because the platform is behind an ingress that terminates TLS and the container has no
    # certificate of its own. Turning it on here produces a pod that redirects to a port nothing serves.
    ASPNETCORE_HTTPS_PORTS=

EXPOSE 8080

# -- the console and API -------------------------------------------------------------------------

FROM runtime AS api
WORKDIR /app
COPY --from=build --chown=64198:64198 /app/api ./

# Never migrates. Several API replicas racing to apply one migration is how a half-applied schema
# happens; the deployment runs a Job for that instead.
ENV Database__MigrateOnStartup=false

ENTRYPOINT ["dotnet", "Sentinel.Api.dll"]

# -- the detection engine ------------------------------------------------------------------------

FROM runtime AS engine
WORKDIR /app
COPY --from=build --chown=64198:64198 /app/engine ./

# Also false. It is the single writer of the schema when run by hand, but in Kubernetes the migration
# Job owns that — an engine that migrated on startup would race its own replicas.
ENV Database__MigrateOnStartup=false

ENTRYPOINT ["dotnet", "Sentinel.Engine.dll"]
