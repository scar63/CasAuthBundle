<?php

namespace YRaiso\CasAuthBundle\EventListener;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Contracts\EventDispatcher\Event;

class CASAuthenticationFailureEvent extends Event {

    const POST_MESSAGE = 'cas_auth.authentication.failure';

    private $request;
    private $exception;
    private $response;

    public function __construct(Request $request, AuthenticationException $exception, Response $response) {
        $this->request = $request;
        $this->exception = $exception;
        $this->response = $response;
    }

    /**
     * @return Response
     */
    public function getResponse(): Response
    {
        return $this->response;
    }

    /**
     * @return Request
     */
    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * @return AuthenticationException
     */
    public function getException(): AuthenticationException
    {
        return $this->exception;
    }

    /**
     * @return string
     */
    public function getExceptionType(): string
    {
        return get_class($this->exception);
    }

    /**
     * @param Response $response
     */
    public function setResponse(Response $response) {
        $this->response = $response;
    }

}