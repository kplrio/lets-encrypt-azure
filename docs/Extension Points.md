Here are some pointers on where you can drop extensions to cover more than the Azure serices already covered. Because this function acts as a dependency enabler, you need to understand how the end result works and is set up before you begin to modify it.

# Areas of Focus 
  
  
- The `sample.json` in `LetsEncrypt.Func` is the first file you're going to want to review. Beyond the exaplanations provided within, there's a few key elements with implications on extending functionality cover to new service types. 
  - The first element, `/acme`, exampliains to an extent, and implies even more the flow of the ACME protocol if you are not already familiar with it. Thought this part is covered implementation-wise, you should still understand how it works. There shouldn't be any need to interface with or extend anything in the `LetsEncrypt.Logic.Acme` namespace.
  - `/certificates` is a bit misleading at first. It contains an array of certificate objects at the top level. You can think of this object as more of an "ACME Certificate Driver Config" rather than just a certificate. Within this object are elements to define:
    - hostnames
    - challenge response factories
    - storage mechanisms
    - target resource
  - Though the target resource is ultimately responsible the prior three, it's just a sibling object here.
  - The array makes use of "fallbacks" to lessen the config file length. Though I disagree with the design here due it's confusing nature, we won't be changing it, or modifying it. So for example an API Gateway config added to this might look like this:
  
```json
  {
    "hostnames": [ "example.com", "www.example.com", "sub.zone.example.com" ],
    "targetResource": {
      "type": "AzApiGateway",
      "name": "example-api-gw"
    }
  }
```

  - A config set up as such with the existing codebase will cover the prior elements. Leaving you with only a couple pieces to implement.
- `ITargetResource` in the `LetsEncrypt.Logic.Providers.TargetResources` namespace is next up. It's an interface with only a few very generic definitions requring only three concrete implementations, and two definitions that are essentially reflections of configuration values:
  - `bool SupportsCertificateCheck { get; }` - this is typical MS style design `SupportsXXXXX` is littered all over the place. If it didn't support certificate checks, we would not be using this to automate it. So this may require a concrete definition, but it'll simply be return the value of `true`
  - `Task<bool> IsUsingCertificateAsync(ICertificate cert, CancellationToken cancellationToken);` - A check to see if the target resource already has a certificate, or needs a new one.
  - `Task UpdateAsync(ICertificate cert, CancellationToken cancellationToken);` A method to add/update the certificate on the target resource. Though the name implies updating only, this is where you also define the initial creation.
- `AppServiceTargetResource` in the same namespace is a good reference for how to build out a new certificate driver/provider. It's well documented in the areas it needs to be with comments. It also shares logic with many other API web style services with TLS certficate support. For example this particular block is necessary for API gateways as well: 

    ```csharp
     // app service has one entry per domain, but we could have one cert that matched all
     var matched = response.CustomDomains.Where(x => cert.Thumbprint.Equals(x.Thumbprint, StringComparison.OrdinalIgnoreCase))
    ```

    Followed by a comparison to the host name in the return block:

    ```csharp
    // verify that the cert covers all matching entries
    return matched.All(x => cert.HostNames.Contains(x.HostName, StringComparison.OrdinalIgnoreCase));
    ```
  - This makes use of an `IAzureAppServiceClient` that is manually defined in the `LetsEncrypt.Logic.Azure` namespace. If not using AutoRest, you'll need to define one for your service as well.
  - If using AutoRest, create an `Azure[TargetServiceType]Client` as just a simple wrapper around the generated classes. Doing so follows the existing pattern, and will reduce merge conflicts from the upstream repositories.



