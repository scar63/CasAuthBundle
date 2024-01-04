<?php

namespace YRaiso\CasAuthBundle\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class AuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    protected $server_login_url;
    protected $query_service_parameter;
    protected $server_force_redirect_https;

    /**
     * @param $config
     */
    public function __construct($config)
    {
        $this->server_login_url = $config['server_login_url'];
        $this->query_service_parameter = $config['query_service_parameter'];
        $this->server_force_redirect_https = $config['server_force_redirect_https'] ?? false;
    }

    /**
     * @param Request $request
     * @param AuthenticationException|null $authException
     * @return RedirectResponse
     */
    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        $uri = $request->getUri();
        if($this->server_force_redirect_https && $request->getScheme() === 'http')
            $uri = preg_replace("/^http:/i", "https:", $request->getUri());

        return new RedirectResponse($this->server_login_url.'?'.$this->query_service_parameter.'='.urlencode($uri));
    }
}