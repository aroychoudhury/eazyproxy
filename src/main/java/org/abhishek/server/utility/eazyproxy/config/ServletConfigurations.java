/**
 * Copyright Abhishek Roychoudhury (https://github.com/aroychoudhury)
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

import org.abhishek.server.utility.eazyproxy.servlet.EazyProxyServlet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Added on 11-Nov-2017.
 * 
 * @author abhishek
 * @since 11.2017-RELEASE
 */
@Configuration
public class ServletConfigurations {
    @Value("${eazyproxy.log:false}")
    private boolean log = false;

    @Value("${eazyproxy.forward.client-ip:true}")
    private boolean forwardIP = true;

    @Value("${eazyproxy.forward.url-fragment:true}")
    private boolean sendUrlFragment = true;

    @Value("${eazyproxy.preserve.host:true}")
    private boolean preserveHost = false;

    @Value("${eazyproxy.preserve.cookies:true}")
    private boolean preserveCookies = false;

    @Value("${eazyproxy.handle.redirects:true}")
    private boolean handleRedirects = false;

    @Value("${eazyproxy.timeout-millis.connect:30000}")
    private int connectTimeout = 30000;

    @Value("${eazyproxy.timeout-millis.read:30000}")
    private int readTimeout = 30000;

    @Bean
    public ServletRegistrationBean servletRegistrationBean(){
        EazyProxyServlet servlet = new EazyProxyServlet();
        servlet.setLog(log);
        servlet.setForwardIP(forwardIP);
        servlet.setHandleRedirects(handleRedirects);
        servlet.setPreserveCookies(preserveCookies);
        servlet.setConnectTimeout(connectTimeout);
        servlet.setReadTimeout(readTimeout);
        servlet.setSendUrlFragment(sendUrlFragment);
        return new ServletRegistrationBean(servlet,"/*");
    }
}
