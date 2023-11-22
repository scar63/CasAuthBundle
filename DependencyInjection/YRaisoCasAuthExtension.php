<?php

namespace YRaiso\CasAuthBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class YRaisoCasAuthExtension extends Extension implements PrependExtensionInterface
{

    /**
     * @param array $configs
     * @param ContainerBuilder $container
     * @return void
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $authenticator = $container->autowire('yraiso.cas_authenticator',
            'YRaiso\CasAuthBundle\Security\CasAuthenticator');
        $authenticator->setArguments(array($config));

        $entryPoint = $container->autowire('yraiso.cas_auth_entry_point',
            'YRaiso\CasAuthBundle\Security\AuthenticationEntryPoint');
        $entryPoint->setArguments(array($config));

        $container->register('yraiso.cas_user_provider',
            'YRaiso\CasAuthBundle\Security\User\CasUserProvider');
    }

    /**
     * @param ContainerBuilder $container
     * @return void
     */
    public function prepend(ContainerBuilder $container)
    {
        // TODO: Implement prepend() method.
    }
}