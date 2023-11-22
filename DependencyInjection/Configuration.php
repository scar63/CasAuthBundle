<?php

namespace YRaiso\CasAuthBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    /**
     * @return TreeBuilder
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('y_raiso_cas_auth');

        $rootNode = $treeBuilder->getRootNode();
        $rootNode
            ->children()
            ->scalarNode('server_login_url')->end()
            ->scalarNode('server_validation_url')->end()
            ->scalarNode('server_logout_url')->end()
            ->scalarNode('xml_namespace')
            ->defaultValue('cas')
            ->end()
            ->arrayNode('options')
            ->prototype('scalar')->end()
            ->defaultValue(array())
            ->end()
            ->scalarNode('username_attribute')
            ->defaultValue('user')
            ->end()
            ->scalarNode('query_ticket_parameter')
            ->defaultValue('ticket')
            ->end()
            ->scalarNode('query_service_parameter')
            ->defaultValue('service')
            ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}