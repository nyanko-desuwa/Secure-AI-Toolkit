# .NET Dependency Injection and DbContext Lifetimes

Verified 2026-07-28 against Microsoft Learn:

- <https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection>
- <https://learn.microsoft.com/en-us/ef/core/dbcontext-configuration/>

These are the named framework sources for this skill's lifetime examples. Other containers differ;
do not transfer .NET behaviour to NestJS, Spring, FastAPI, or another container without checking
that container's documentation.

## Service Lifetimes

The built-in .NET container supports transient, scoped, and singleton lifetimes.

| Lifetime | Practical meaning | Clean Architecture use here |
|---|---|---|
| Transient | A new instance when resolved | Small stateless objects that own no expensive resource |
| Scoped | One instance per scope | Use case, repository, actor/tenant context, `DbContext` |
| Singleton | One instance for the application lifetime | Stateless process services and explicitly bounded shared caches |

A lifetime is part of correctness, not a performance decoration. A longer-lived service may not
capture a shorter-lived dependency. If a singleton captures a scoped actor, the actor can outlive
the request and be served to later requests. If it captures a `DbContext`, the context, tracked
entities, and underlying resources can be retained until application shutdown.

## Scope Validation

Microsoft's dependency injection documentation says scoped services are disposed by the container
that created them. If a scoped service is created in the root container, its lifetime is
effectively promoted to singleton because the root disposes it only when the application shuts
down.

When an application runs in Development and uses `CreateApplicationBuilder`, the default provider
checks that:

- scoped services are not resolved from the root service provider;
- scoped services are not injected into singletons.

These checks occur when the service provider is built. This is the framework mechanism referred
to as scope validation in the examples. Run an application boot test with validation enabled in
CI; a check available only on a developer's machine is not a reliable gate.

Scope validation does not inspect arbitrary runtime state. A static variable, a factory closure,
a service locator, or an instance manually passed to a singleton can still capture request data
without the constructor graph revealing it.

## DbContext Lifetime

The EF Core documentation states that a `DbContext` is designed for a single unit of work and its
lifetime is usually short. It begins when created and ends when disposed.

`AddDbContext` registers a `DbContext` as scoped by default. In a typical ASP.NET Core application,
each request has a separate scope, so a separate context is created for the request and disposed
when the request ends.

The source also states:

- a `DbContext` must be disposed after use so unmanaged resources are freed and hooks are
  unregistered;
- `DbContext` is not thread-safe and must not be shared between threads;
- asynchronous operations must be awaited before the same context is used again;
- an `InvalidOperationException` from EF Core can leave a context in an unrecoverable state.

These are why a singleton use case or service must not hold a context. It is not merely a longer
cache lifetime: concurrent requests can use the same non-thread-safe unit of work, and its change
tracker retains every loaded entity until shutdown.

## Hosted Services and Scopes

A hosted service is registered as a singleton. Microsoft's DI documentation instructs hosted
services that need scoped dependencies to inject `IServiceScopeFactory`, create a scope, resolve
the scoped dependencies within that scope, perform one unit of work, and dispose the scope.

```csharp
public sealed class Worker(IServiceScopeFactory scopes) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using var scope = scopes.CreateScope();
            var useCase = scope.ServiceProvider.GetRequiredService<ProcessMessage>();
            await useCase.ExecuteAsync(Actor.System("worker"), stoppingToken);
        }
    }
}
```

The example is adapted to this skill's vocabulary. The actor is explicit; it is not pulled from a
request context that does not exist in a worker.

## Factory-Created Contexts

EF Core documents `AddDbContextFactory` for cases where the DI scope does not align with the
desired unit of work, or where one scope contains multiple units of work. Contexts created by the
factory are not managed by the application's service provider and must be disposed by the
application.

This is the ownership rule used throughout this skill:

- the container disposes objects it creates inside a scope;
- code that creates a scope disposes the scope;
- code that creates a context from a factory disposes the context;
- an instance constructed manually and passed to the container remains the application's disposal
  responsibility unless the specific registration API documents otherwise.

Verify the last point for the registration API in use; container ownership of prebuilt instances
is a framework-specific behaviour.

## Security and Resource Implications

| Misconfiguration | Security effect | Resource effect |
|---|---|---|
| Singleton captures actor/tenant | First or stale identity leaks across requests (`A01:2025`, `CWE-488`) | Request graph retained for process lifetime |
| Singleton captures `DbContext` | Cross-request state and unsafe concurrent access | Connection, change tracker, and entities retained |
| Worker resolves scoped service from root | Tenant/unit-of-work state is shared | Disposed only at shutdown |
| Factory context is not disposed | No direct authorization mapping by itself | Connections and hooks accumulate (`CWE-772`) |
| Singleton cache omits tenant key | One tenant receives another tenant's value (`A01:2025`) | Cache can grow without bound if also uncapped |

Heap diagnosis, retained-reference analysis, and cache sizing belong to
`skills/architecture/performance/`. This reference establishes the lifetime contract only.

## Verification Notes

- Microsoft Learn content was fetched and checked on 2026-07-28.
- The DI page metadata showed a 2026 update; the EF Core page described current `AddDbContext`
  behaviour. This skill does not pin a .NET or EF Core version number.
- Code examples use APIs documented on those pages. Verify overloads and defaults against the
  target framework version before copying them.
- No claim is made that scope validation runs in every environment by default; the documented
  default described is Development with `CreateApplicationBuilder`.
