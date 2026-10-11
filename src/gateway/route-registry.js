export function createRouteRegistry(config) {
  return [{
    id: 'catalog',
    publicPrefix: '/api/catalog',
    upstreamUrl: config.services.catalog,
    upstreamPathPrefix: '',
    requiredScope: 'catalog:read'
  }];
}
