# Overview
   
Here are some pointers on where you can drop extensions to cover more than the Azure serices already covered.

## Areas of Focus
   
  
- The sample.json is the first file you're going to want to review. Beyond the exaplanations provided within, there's a few key elements with implications on extending functionality cover to new service types. 
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
