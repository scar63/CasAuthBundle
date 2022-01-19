<?php

namespace YRaiso\CasAuthBundle\EventListener;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutListener
{
    private $logoutUrl;

    /**
     * @param string $logoutUrl
     */
    public function __construct(string $logoutUrl)
    {
        $this->logoutUrl = $logoutUrl;
    }

    /**
     * @param LogoutEvent $logoutEvent
     * @return void
     */
    public function onSymfonyComponentSecurityHttpEventLogoutEvent(LogoutEvent $logoutEvent): void
    {
        $logoutEvent->setResponse(new RedirectResponse($this->logoutUrl, Response::HTTP_MOVED_PERMANENTLY));
    }
}