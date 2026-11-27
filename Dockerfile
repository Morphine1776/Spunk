FROM node:22-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src/Spunk.Core/ src/Spunk.Core/
COPY src/Spunk.Infrastructure/ src/Spunk.Infrastructure/
COPY src/Spunk.Api/ src/Spunk.Api/
RUN dotnet publish src/Spunk.Api/Spunk.Api.csproj -c Release -o /out
COPY --from=web /src/src/Spunk.Api/wwwroot /out/wwwroot

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_URLS=http://+:8080 \
    Ingest__UdpPort=514 \
    Ingest__TcpPort=514
EXPOSE 8080 514/udp 514/tcp
ENTRYPOINT ["dotnet", "Spunk.Api.dll"]
