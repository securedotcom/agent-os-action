# Dashboard/UI Performance Checklist

## Bundle Optimization
- [ ] **Code Splitting**: Lazy loading for routes
- [ ] **Tree Shaking**: Unused code eliminated
- [ ] **Minification**: Production builds minified
- [ ] **Bundle Size**: Main bundle < 250KB gzipped
- [ ] **Dependency Audit**: No unnecessary dependencies

## Rendering Performance
- [ ] **React.memo/useMemo**: Expensive components memoized
- [ ] **Virtualization**: Long lists virtualized
- [ ] **Image Optimization**: Images compressed and lazy-loaded
- [ ] **Web Vitals**: LCP < 2.5s, FID < 100ms, CLS < 0.1
- [ ] **Lighthouse Score**: Performance score > 90

## Caching & Loading
- [ ] **Service Worker**: PWA caching implemented
- [ ] **Static Assets**: Long cache headers on static files
- [ ] **API Caching**: Appropriate cache strategies
- [ ] **Prefetching**: Critical resources prefetched
- [ ] **Loading States**: Skeleton screens for async data

## Merge Blockers
- **[BLOCKER]** Bundle size > 500KB gzipped
- **[BLOCKER]** Blocking render for >3 seconds
- **[BLOCKER]** Memory leaks in components
- **[BLOCKER]** No lazy loading on large lists (>1000 items)

