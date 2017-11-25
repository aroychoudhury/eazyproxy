/**
 * Copyright Abhishek Roychoudhury (https://github.com/aroychoudhury)
 * 
 * Heavily inspired and adapted from:
 * https://github.com/spring-cloud/spring-cloud-netflix
 * 
 * Configurations have been adopted from spring-cloud-netflix project:
 * org.springframework.cloud.netflix.zuul.filters.ZuulProperties
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
package org.abhishek.server.utility.eazyproxy.config;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.abhishek.server.utility.eazyproxy.bean.ProxyRoute;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * Added on 11-Nov-2017.
 * 
 * @author abhishek
 * @since 11.2017-RELEASE
 */
@Configuration
@ConfigurationProperties("eazyproxy")
public class ProxyConfigurations {
    /**
     * A common prefix for all routes.
     */
    private String prefix = "";

    /**
     * Flag saying whether to strip the prefix from the path before forwarding.
     */
    private boolean stripPrefix = true;

    /**
     * Flag for whether retry is supported by default (assuming the routes themselves
     * support it).
     */
    private Boolean retryable = false;

    /**
     * Define the retry interval in milliseconds. Ignored if the
     * {@link ProxyConfigurations#retryable} flag is set to false.
     */
    private Integer retryInterval;

    /**
     * Set of service names not to consider for proxying automatically. By default all
     * services in the discovery client will be proxied.
     */
    private Set<String> ignoredServices = new LinkedHashSet<>();

    /**
     * Set of path patterns not to be considered for proxying automatically.
     * Ignored patterns span all services and supersede any other route
     * specification.
     */
    private Set<String> ignoredPatterns = new LinkedHashSet<>();

    /**
     * Names of HTTP headers to ignore completely (i.e. leave them out of downstream
     * requests and drop them from downstream responses).
     */
    private Set<String> ignoredHeaders = new LinkedHashSet<>();

    /**
     * Map of route names to properties.
     */
    private Map<String, ProxyRoute> routes = new LinkedHashMap<>();

    @PostConstruct
    public void init() {
        for (Entry<String, ProxyRoute> entry : this.routes.entrySet()) {
            ProxyRoute value = entry.getValue();
            if (!StringUtils.hasText(value.getId())) {
                value.setId(entry.getKey());
            }
            if (!StringUtils.hasText(value.getPath())) {
                value.setPath("/" + entry.getKey() + "/**");
            }
        }
    }

    public String getPrefix() {
        return prefix;
    }

    public boolean isStripPrefix() {
        return stripPrefix;
    }

    public Boolean getRetryable() {
        return retryable;
    }

    public Integer getRetryInterval() {
        return retryInterval;
    }

    public Set<String> getIgnoredHeaders() {
        return ignoredHeaders;
    }

    public Set<String> getIgnoredPatterns() {
        return ignoredPatterns;
    }

    public Set<String> getIgnoredServices() {
        return ignoredServices;
    }

    public Map<String, ProxyRoute> getRoutes() {
        return routes;
    }
}
