var builder = DistributedApplication.CreateBuilder(args);

var sql = builder.AddSqlServer("sql")
                 .WithDataVolume()
                 .WithLifetime(ContainerLifetime.Persistent);

var identitydb = sql.AddDatabase("identitydb");

var apiService = builder.AddProject<Projects.MissioneNataleProtetto_ApiService>("apiservice")
    .WithHttpHealthCheck("/health");

builder.AddProject<Projects.MissioneNataleProtetto_Web>("webfrontend")
    .WithExternalHttpEndpoints()
    .WithHttpHealthCheck("/health")
    .WithReference(identitydb)
    .WaitFor(identitydb)
    .WithReference(apiService)
    .WaitFor(apiService);

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
    .WaitFor(identitydb);

builder.Build().Run();
