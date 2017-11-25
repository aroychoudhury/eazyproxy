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
package org.abhishek.server.utility.eazyproxy.context;

import org.abhishek.server.utility.eazyproxy.service.UrlResolutionServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * Added on 15-Oct-2017.
 * 
 * @author abhishek
 * @since 10.2017-RELEASE
 */
@Component
public final class AppContext implements ApplicationContextAware {
    private static final Logger log = LoggerFactory.getLogger(AppContext.class);

    private static ApplicationContext context;

    /**
     * @author Abhishek
     * @since Oct.2017-RELEASE
     * @see org.springframework.context.ApplicationContextAware#setApplicationContext(org.springframework.context.ApplicationContext)
     */
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        try {
            if (null != applicationContext) {
                context = applicationContext;
            }
        } catch (Exception e) {
            log.error("ApplicationContext could not be set : ", e);
            throw e;
        }
    }

    /**
     * @author abhishek
     * @since 10.2017-RELEASE
     * @param beanName Name of the Bean being requested
     * @return Instance of the requested Bean
     */
    @SuppressWarnings("unchecked")
    private static <T> T getBean(String beanName) {
        try {
            return (T) context.getBean(beanName);
        } catch (Exception e) {
            log.error("Bean could not be retrieved : ", e);
            throw e;
        }
    }

    public static UrlResolutionServices url() {
        return getBean("UrlResolutionServices");
    }
}
