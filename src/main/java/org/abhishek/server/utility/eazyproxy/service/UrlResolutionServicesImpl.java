/**
 * Copyright Abhishek Roychoudhury (https://github.com/aroychoudhury)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.abhishek.server.utility.eazyproxy.service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicReference;

import org.abhishek.server.utility.eazyproxy.bean.ProxyRoute;
import org.abhishek.server.utility.eazyproxy.bean.Route;
import org.abhishek.server.utility.eazyproxy.config.ProxyConfigurations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

/**
 * Added on 15-Oct-2017.
 * 
 * @author abhishek
 * @since 10.2017-RELEASE
 */
@Service("UrlResolutionServices")
public class UrlResolutionServicesImpl implements UrlResolutionServices {
    private static final Logger log = LoggerFactory.getLogger(UrlResolutionServicesImpl.class);

    private static final String SCHEME_SEPARATOR = "://";
    private static final String URL_PATH_SEPARATOR = "/";

    @Value("app.eazyproxy.default")
    private String defaultUrl;

    @Autowired
    private ProxyConfigurations configurations;

    private AtomicReference<Map<String, ProxyRoute>> routes = new AtomicReference<>();

    private PathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Compute a map of path pattern to route. The default is just a static map from the
     * {@link ZuulProperties}, but subclasses can add dynamic calculations.
     */
    protected Map<String, ProxyRoute> locateRoutes() {
        LinkedHashMap<String, ProxyRoute> routesMap = new LinkedHashMap<String, ProxyRoute>();
        for (ProxyRoute route : this.configurations.getRoutes().values()) {
            routesMap.put(route.getPath(), route);
        }
        return routesMap;
    }

    protected Map<String, ProxyRoute> getRoutesMap() {
        if (this.routes.get() == null) {
            this.routes.set(this.locateRoutes());
        }
        return this.routes.get();
    }

    protected Route getMatchingRoute(final String path) {
        if (log.isDebugEnabled()) {
            log.debug("Finding route for path: " + path);
        }

        // This is called for the initialization done in getRoutesMap()
        this.getRoutesMap();

        if (log.isDebugEnabled()) {
            log.debug("servletPath=" + "");
        }

        ProxyRoute route = this.getProxyRoute(path);

        return this.getRoute(route, path);
    }

    protected ProxyRoute getProxyRoute(String adjustedPath) {
        if (!this.matchesIgnoredPatterns(adjustedPath)) {
            for (Entry<String, ProxyRoute> entry : this.getRoutesMap().entrySet()) {
                String pattern = entry.getKey();
                log.debug("Matching pattern:" + pattern);
                if (this.pathMatcher.match(pattern, adjustedPath)) {
                    return entry.getValue();
                }
            }
        }
        return null;
    }

    protected boolean matchesIgnoredPatterns(String path) {
        for (String pattern : this.configurations.getIgnoredPatterns()) {
            log.debug("Matching ignored pattern:" + pattern);
            if (this.pathMatcher.match(pattern, path)) {
                log.debug("Path " + path + " matches ignored pattern " + pattern);
                return true;
            }
        }
        return false;
    }

    protected Route getRoute(ProxyRoute route, String path) {
        if (route == null) {
            return null;
        }
        if (log.isDebugEnabled()) {
            log.debug("route matched=" + route);
        }

        String targetPath = path;
        String prefix = this.configurations.getPrefix();
        if (path.startsWith(prefix) && this.configurations.isStripPrefix()) {
            targetPath = path.substring(prefix.length());
        }

        if (route.isStripPrefix()) {
            int index = route.getPath().indexOf("*") - 1;
            if (index > 0) {
                String routePrefix = route.getPath().substring(0, index);
                targetPath = targetPath.replaceFirst(routePrefix, "");
                prefix = prefix + routePrefix;
            }
        }

        Boolean retryable = this.configurations.getRetryable();
        if (route.getRetryable() != null) {
            retryable = route.getRetryable();
        }

        Integer retryInterval = this.configurations.getRetryInterval();
        if (route.getRetryInterval() != null) {
            retryInterval = route.getRetryInterval();
        }

        return new Route(
                route.getId(), 
                targetPath, 
                route.getLocation(), 
                prefix,
                retryable,
                retryInterval,
                route.isCustomSensitiveHeaders() ? route.getSensitiveHeaders() : null,
                route.isStripPrefix());
    }

    /**
     * @author Abhishek
     * @since Nov.2017-RELEASE
     * @see org.abhishek.server.utility.eazyproxy.service.UrlResolutionServices#get(java.lang.String)
     */
    @Override
    public String get(String requestUrl) {
        try {
            Route matchedRoute = this.getMatchingRoute(requestUrl);
            String matchedRouteUrl = matchedRoute.getLocation() + matchedRoute.getPath();
            log.info("Initial Route : {}", requestUrl);
            log.info("Matched Route : {}", matchedRouteUrl);
            return matchedRouteUrl;
        } catch (NullPointerException ne) {
            // no route found
            return "";
        }
    }

    /**
     * @author Abhishek
     * @since Nov.2017-RELEASE
     * @see org.abhishek.server.utility.eazyproxy.service.UrlResolutionServices#getHost(java.lang.String)
     */
    @Override
    public String getHost(String requestUrl) {
        try {
            Route matchedRoute = this.getMatchingRoute(requestUrl);
            String matchedHost = matchedRoute.getLocation();

            int schemeEndIdx = matchedHost.indexOf(SCHEME_SEPARATOR) + SCHEME_SEPARATOR.length() + 1;
            int hostEndIdx = matchedHost.indexOf(URL_PATH_SEPARATOR, schemeEndIdx);

            // check if only host information is added into the configuration
            if (-1 == hostEndIdx)
                return matchedHost;
            else
                return matchedHost.substring(0, hostEndIdx);
        } catch (NullPointerException ne) {
            // no route found
            return "";
        }
    }
}
