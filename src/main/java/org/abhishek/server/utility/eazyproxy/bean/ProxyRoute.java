/**
 * Copyright Abhishek Roychoudhury (https://github.com/aroychoudhury)
 * 
 * Heavily inspired and adapted from:
 * https://github.com/spring-cloud/spring-cloud-netflix
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
package org.abhishek.server.utility.eazyproxy.bean;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.util.StringUtils;

/**
 * Added on 20-Nov-2017.
 * 
 * @author abhishek
 * @since 11.2017-RELEASE
 */
public class ProxyRoute {
    /**
     * The ID of the route (the same as its map key by default).
     */
    private String id;

    /**
     * The path (pattern) for the route, e.g. /foo/**.
     */
    private String path;

    /**
     * A full physical URL to map to the route. An alternative is to use a
     * service ID and service discovery to find the physical address.
     */
    private String url;

    /**
     * Flag to determine whether the prefix for this route (the path, minus
     * pattern patcher) should be stripped before forwarding.
     */
    private boolean stripPrefix = true;

    /**
     * Flag to indicate that this route should be retryable (if supported).
     * The default for retryable is true;
     */
    private Boolean retryable = Boolean.TRUE;

    /**
     * Define the retry interval in milliseconds. Ignored if the
     * {@link ProxyRoute#retryable} flag is set to false. By default a total
     * of 3 retries would be attempted at the mentioned frequency specified
     * below. The default setting for the retry is 300ms.
     */
    private Integer retryInterval = Integer.valueOf(300);

    /**
     * List of sensitive headers that are not passed to downstream requests.
     * Defaults to a "safe" set of headers that commonly contain user
     * credentials. It's OK to remove those from the list if the downstream
     * service is part of the same system as the proxy, so they are sharing
     * authentication data. If using a physical URL outside your own domain,
     * then generally it would be a bad idea to leak user credentials.
     */
    private Set<String> sensitiveHeaders = new LinkedHashSet<>();

    private boolean customSensitiveHeaders = false;

    public ProxyRoute() {
    }

    public ProxyRoute(String id,
            String path,
            String url,
            boolean stripPrefix,
            Boolean retryable,
            Integer retryInterval,
            Set<String> sensitiveHeaders) {
        this.id = id;
        this.path = path;
        this.url = url;
        this.stripPrefix = stripPrefix;
        this.retryable = retryable;
        this.retryInterval = retryInterval;
        this.sensitiveHeaders = sensitiveHeaders;
        this.customSensitiveHeaders = sensitiveHeaders != null;
    }

    public ProxyRoute(String text) {
        String location = null;
        String path = text;
        if (text.contains("=")) {
            String[] values = StringUtils.trimArrayElements(StringUtils.split(text, "="));
            location = values[1];
            path = values[0];
        }
        this.id = extractId(path);
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        setLocation(location);
        this.path = path;
    }

    public ProxyRoute(String path, String location) {
        this.id = extractId(path);
        this.path = path;
        setLocation(location);
    }

    public String getLocation() {
        return this.url;
    }

    public void setLocation(String location) {
        if (location != null && (location.startsWith("http:") || location.startsWith("https:"))) {
            this.url = location;
        }
    }

    private String extractId(String path) {
        path = path.startsWith("/") ? path.substring(1) : path;
        path = path.replace("/*", "").replace("*", "");
        return path;
    }

    public Route getRoute(String prefix) {
        return new Route(this.id,
                this.path,
                getLocation(),
                prefix,
                this.retryable,
                this.retryInterval,
                isCustomSensitiveHeaders() ? this.sensitiveHeaders : null,
                this.stripPrefix);
    }

    public void setSensitiveHeaders(Set<String> headers) {
        this.customSensitiveHeaders = true;
        this.sensitiveHeaders = new LinkedHashSet<>(headers);
    }

    public boolean isCustomSensitiveHeaders() {
        return this.customSensitiveHeaders;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isStripPrefix() {
        return stripPrefix;
    }

    public void setStripPrefix(boolean stripPrefix) {
        this.stripPrefix = stripPrefix;
    }

    public Boolean getRetryable() {
        return retryable;
    }

    public void setRetryable(Boolean retryable) {
        this.retryable = retryable;
    }

    public Integer getRetryInterval() {
        return retryInterval;
    }

    public void setRetryInterval(Integer retryInterval) {
        this.retryInterval = retryInterval;
    }

    public Set<String> getSensitiveHeaders() {
        return sensitiveHeaders;
    }

    public void setCustomSensitiveHeaders(boolean customSensitiveHeaders) {
        this.customSensitiveHeaders = customSensitiveHeaders;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ProxyRoute that = (ProxyRoute) o;
        return customSensitiveHeaders == that.customSensitiveHeaders
                && Objects.equals(id, that.id)
                && Objects.equals(path, that.path)
                && Objects.equals(retryable, that.retryable)
                && Objects.equals(retryInterval, that.retryInterval)
                && Objects.equals(sensitiveHeaders, that.sensitiveHeaders)
                && stripPrefix == that.stripPrefix
                && Objects.equals(url, that.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(customSensitiveHeaders,
                id,
                path,
                retryable,
                retryInterval,
                sensitiveHeaders,
                stripPrefix,
                url);
    }

    @Override
    public String toString() {
        return new StringBuilder("ProxyRoute{")
                .append("id='").append(id).append("', ")
                .append("path='").append(path).append("', ")
                .append("url='").append(url).append("', ")
                .append("stripPrefix=").append(stripPrefix).append(", ")
                .append("retryable=").append(retryable).append(", ")
                .append("retryInterval=").append(retryInterval).append(", ")
                .append("sensitiveHeaders=").append(sensitiveHeaders).append(", ")
                .append("customSensitiveHeaders=").append(customSensitiveHeaders).append(", ")
                .append("}")
                .toString();
    }
}
