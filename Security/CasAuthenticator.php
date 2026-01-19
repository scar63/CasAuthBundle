<?php

namespace YRaiso\CasAuthBundle\Security;

use Exception;
use SimpleXMLElement;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Contracts\HttpClient\Exception\ClientExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\RedirectionExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\ServerExceptionInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use YRaiso\CasAuthBundle\EventListener\CASAuthenticationFailureEvent;
class CasAuthenticator extends AbstractAuthenticator
{
    protected $server_login_url;
    protected $server_validation_url;
    protected $xml_namespace;
    protected $username_attribute;
    protected $query_ticket_parameter;
    protected $query_service_parameter;
    protected $server_force_redirect_https;
    protected $options;
    private $eventDispatcher;
    private $client;

    /**
     * @param $config
     * @param HttpClientInterface $client
     * @param EventDispatcherInterface $eventDispatcher
     */
    public function __construct($config, HttpClientInterface $client, EventDispatcherInterface $eventDispatcher)
    {
        $this->server_login_url = $config['server_login_url'];
        $this->server_validation_url = $config['server_validation_url'];
        $this->xml_namespace = $config['xml_namespace'];
        $this->username_attribute = $config['username_attribute'];
        $this->query_service_parameter = $config['query_service_parameter'];
        $this->query_ticket_parameter = $config['query_ticket_parameter'];
        $this->server_force_redirect_https = $config['server_force_redirect_https'];
        $this->options = $config['options'];
        $this->eventDispatcher = $eventDispatcher;
        $this->client = $client;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning `false` will cause this authenticator
     * to be skipped.
     * @param Request $request
     * @return bool|null
     */
    public function supports(Request $request): ?bool
    {
        return $request->query->has($this->query_ticket_parameter);
    }

    /**
     * @param Request $request
     * @return Passport
     * @throws ClientExceptionInterface
     * @throws RedirectionExceptionInterface
     * @throws ServerExceptionInterface
     * @throws TransportExceptionInterface
     * @throws Exception
     */
    public function authenticate(Request $request): Passport
    {
       $url = $this->server_validation_url.'?'.$this->query_ticket_parameter.'='.
            $request->get($this->query_ticket_parameter).'&'.
            $this->query_service_parameter.'='.urlencode($this->removeCasTicket($request->getUri()));

       $response = $this->client->request('GET', $url, $this->options);
        $xml = new SimpleXMLElement($response->getContent(), 0, false, $this->xml_namespace, true);

        if (property_exists($xml, 'authenticationSuccess') && $xml->authenticationSuccess !== null) {
            $infoUser = (array)$xml->authenticationSuccess[0];
            $passport = new SelfValidatingPassport(new UserBadge($infoUser['user']));
            if(!empty($infoUser['attributes']))
                foreach ((array)$infoUser['attributes'] as $attributeName => $attributeValue)
                    $passport->setAttribute($attributeName, $attributeValue);
            return $passport;
        }
        else {
            throw new CustomUserMessageAuthenticationException('Authentication failed! Try again');
        }
    }

    /**
     * @param Request $request
     * @param TokenInterface $token
     * @param string $firewallName
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        if ($request->query->has($this->query_ticket_parameter)) {
            return new RedirectResponse($this->removeCasTicket($request->getUri()));
        }
        else {
            return null; // on success, let the request continue
        }
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        ];

        $def_response = new JsonResponse($data, Response::HTTP_FORBIDDEN);
        $event = new CASAuthenticationFailureEvent($request,$exception, $def_response);
        $this->eventDispatcher->dispatch($event, CASAuthenticationFailureEvent::POST_MESSAGE);

        return $event->getResponse();
    }

    /**
     * Strip the CAS 'ticket' parameter from a uri.
     * @param $uri
     * @return string
     */
    protected function removeCasTicket($uri): string
    {
        $parsed_url = parse_url($uri);
        // If there are no query parameters, then there is nothing to do.
        if (empty($parsed_url['query'])) {
            return $uri;
        }
        parse_str($parsed_url['query'], $query_params);
        // If there is no 'ticket' parameter, there is nothing to do.
        if (!isset($query_params[$this->query_ticket_parameter])) {
            return $uri;
        }
        // Remove the ticket parameter and rebuild the query string.
        unset($query_params[$this->query_ticket_parameter]);
        if (empty($query_params)) {
            unset($parsed_url['query']);
        } else {
            $parsed_url['query'] = http_build_query($query_params);
        }

        // Rebuild the URI from the parsed components.
        // Source: https://secure.php.net/manual/en/function.parse-url.php#106731
        $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
        if($this->server_force_redirect_https && $scheme === 'http://')
            $scheme = 'https://';
        $host     = $parsed_url['host'] ?? '';
        $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $user     = $parsed_url['user'] ?? '';
        $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = $parsed_url['path'] ?? '';
        $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
        $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
        return "$scheme$user$pass$host$port$path$query$fragment";
    }

    /**
     * @param Passport $passport
     * @param string $firewallName
     * @return TokenInterface
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $passport->getUser()->setCasAttributes($passport->getAttributes());
        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

}