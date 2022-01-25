# CasAuthBundle
Basic CAS (SSO) authenticator for Symfony 5.4 (no use guard component && no old authentication)

This bundle provides a -very- basic CAS (https://github.com/apereo/cas/tree/4.1.x) authentication client for Symfony 5.4 with new security authentication system

## Installation

Install the library via [Composer](https://getcomposer.org/) by
running the following command:

```bash
composer require yraiso/casauth-bundle
```

Create this file config/packages/y_raiso_cas_auth.yaml, add these settings :
```yaml
y_raiso_cas_auth:
    server_login_url: https://mycasserver/cas/
    server_validation_url: https://mycasserver/cas/serviceValidate
    server_logout_url: https://mycasserver/cas/logout
    xml_namespace: cas
    options: [] # you can add request options (or override global ones) (cf https://symfony.com/doc/current/http_client.html#making-requests)
```
Note : the xml_namespace and options parameters are optionals

Modify your security.yml with the following values (the provider in the following settings should not be used as it's just a very basic example ) :
```yaml
security:
    providers:
        cas_user_provider:
          id: yraiso.cas_user_provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            logout: ~
            remote_user:
              provider: cas_user_provider
            custom_authenticator: yraiso.cas_authenticator
            entry_point: yraiso.cas_auth_entry_point

    access_control:
        - { path: ^/, roles: ROLE_USER }
  ```
In production, create your own UserProvider ( implements UserProviderInterface, PasswordUpgraderInterface) and User (implements UserInterface) then add its service name in providers:cas:id :

services.yaml:

```yaml
# ...
services:
    cas_user_provider:
        class: App\Security\User\CasUserProvider
 ```
  And voila ! Your secured route should redirect you to your CAS login page which should authenticate you.


## CAS global logout option

If you want your users to logout from the remote CAS server when logging out from your app, you should apply the following settings :

services.yaml:

```yaml
# ...
    firewalls:
        # ...
        main:
          # ...
          logout:
            path: app_logout
  ```
  
services.yaml

```yaml
# ...
services:
    # ... 
    YRaiso\CasAuthBundle\EventListener\LogoutListener:
        arguments:
            $logoutUrl: "%cas_server_logout_url%"
        tags:
            - name: 'kernel.event_listener'
            event: 'Symfony\Component\Security\Http\Event\LogoutEvent'
            dispatcher: security.event_dispatcher.main
  ```
Next, you need to create a route for this URL (but not a controller):
```php
    /**
     * @Route("/logout", name="app_logout", methods={"GET"})
     *
     */
    public function logout(): void
    {
        // controller can be blank: it will never be called!
        throw new \Exception('Don\'t forget to activate logout in security.yaml');
    }
  ```
