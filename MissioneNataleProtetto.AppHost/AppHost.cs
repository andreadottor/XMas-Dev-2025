using Aspire.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

var sql = builder.AddSqlServer("sql")
                 .WithDataVolume()
                 .WithLifetime(ContainerLifetime.Persistent);

var identitydb = sql.AddDatabase("identitydb");

var username = builder.AddParameter("username", "admin");
var password = builder.AddParameter("password", secret: true, value: "admin");

var keycloak = builder.AddKeycloak("keycloak", 8080, username, password)
                        .WithDataVolume()
                        //.WithRealmImport("./Realms")
                        //.WithEnvironment("KC_HTTP_ENABLED", "true")
                        //.WithEnvironment("KC_PROXY_HEADERS", "xforwarded")
                        //.WithEnvironment("KC_HOSTNAME_STRICT", "false")
                        .WithLifetime(ContainerLifetime.Persistent);
                      //.WithHttpsEndpoint(8081, 8443);
                      //.WithRealmImport("./Realms");

builder.AddProject<Projects.MissioneNataleProtetto_AuthSample1>("missionenataleprotetto-authsample1")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health");

builder.AddProject<Projects.MissioneNataleProtetto_AuthSample2>("missionenataleprotetto-authsample2")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(identitydb)
    .WaitFor(identitydb);

builder.AddProject<Projects.MissioneNataleProtetto_AuthSample3>("missionenataleprotetto-authsample3")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(identitydb)
    .WaitFor(identitydb)
    .WithReference(keycloak)
    .WaitFor(keycloak);

builder.Build().Run();
