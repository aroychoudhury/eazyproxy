/**
 * Copyright Abhishek Roychoudhury (https://github.com/aroychoudhury)
 * 
 * Heavily inspired and adapted from:
 * https://github.com/mitre/HTTP-Proxy-Servlet 
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
package org.abhishek.server.utility.eazyproxy.servlet;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.abhishek.server.utility.eazyproxy.context.AppContext;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.AbortableHttpRequest;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.HeaderGroup;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Added on 15-Oct-2017.
 * 
 * @author abhishek
 * @since 10.2017-RELEASE
 */
@SuppressWarnings("deprecation")
public class EazyProxyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger log = LoggerFactory.getLogger(EazyProxyServlet.class);

    /** The parameter name for the target (destination) URI to proxy to. */
    protected static final String P_TARGET_URI = "targetUri";
    protected static final String ATTR_TARGET_URI = EazyProxyServlet.class.getSimpleName() + ".targetUri";
    protected static final String ATTR_TARGET_HOST = EazyProxyServlet.class.getSimpleName() + ".targetHost";

    // configurations
    protected boolean doLog = false;
    protected boolean forwardIP = true;
    protected boolean sendUrlFragment = true;
    protected boolean preserveHost = false;
    protected boolean preserveCookies = false;
    protected boolean handleRedirects = false;
    protected int connectTimeout = 30000;
    protected int readTimeout = 30000;

    // internal properties
    private HttpClient proxyClient;

    @Override
    public String getServletInfo() {
        return "A proxy servlet by Abhishek Roychoudhury";
    }

    protected String getTargetUri(HttpServletRequest servletRequest) {
        return AppContext.url().get(servletRequest.getPathInfo());
    }

    protected HttpHost getTargetHost(HttpServletRequest servletRequest) {
        return HttpHost.create(AppContext.url().getHost(servletRequest.getPathInfo()));
    }

    protected String getBaseUri(HttpServletRequest request) {
        String scheme = request.getScheme() + "://";
        String serverName = request.getServerName();
        String serverPort = ((request.getServerPort() == 80) ? "" : ":") + request.getServerPort();
        String contextPath = request.getContextPath();
        return scheme + serverName + serverPort + contextPath;
    }

    /**
     * Reads a configuration parameter. By default it reads servlet init
     * parameters but it can be overridden.
     */
    protected String getConfigParam(String key) {
        return this.getServletConfig().getInitParameter(key);
    }

    @Override
    public void init() throws ServletException {
        try {
            this.proxyClient = this.createHttpClient(this.buildRequestConfig(), this.createSslContext());
        } catch (Exception e) {
            log.error("HttpClient Creation : " + e.getMessage(), e);
        }
    }

    /**
     * Sub-classes can override specific behaviour of {@link RequestConfig}.
     */
    protected RequestConfig buildRequestConfig() {
        // 1. Initialize configurations
        // 2. Handle cookies in servlet
        RequestConfig.Builder builder = RequestConfig.custom()
                .setRedirectsEnabled(handleRedirects)
                .setCookieSpec(CookieSpecs.IGNORE_COOKIES)
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(readTimeout)
                .setCircularRedirectsAllowed(true);
        return builder.build();
    }

    /**
     * Sub-classes can override specific behaviour of {@link SSLContext}.
     */
    protected SSLContext createSslContext() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("SSL");

        // set up a TrustManager that trusts everything
        sslContext.init(null, new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] arg0, String arg1)
                    throws CertificateException {
                log.debug("============== checkClientTrusted =============");
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] arg0, String arg1)
                    throws CertificateException {
                log.debug("============== checkServerTrusted =============");
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                log.debug("============== getAcceptedIssuers =============");
                return null;
            }
        } }, new SecureRandom());

        return sslContext;
    }

    /**
     * Called from {@link #init(javax.servlet.ServletConfig)}. HttpClient offers
     * many opportunities for customization. In any case, it should be
     * thread-safe.
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     **/
    protected HttpClient createHttpClient(final RequestConfig requestConfig, final SSLContext sslContext)
            throws KeyManagementException, NoSuchAlgorithmException {
        HttpClient client = HttpClientBuilder.create()
                .setDefaultRequestConfig(requestConfig)
                .setSSLContext(sslContext)
                .setUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36")
                .build();
        return client;
    }

    /**
     * The http client used.
     * 
     * @see #createHttpClient(RequestConfig)
     */
    protected HttpClient getProxyClient() {
        return proxyClient;
    }

    /**
     * Usually, clients implement {@link Closeable}. So close everything on
     * destroy.
     */
    @Override
    public void destroy() {
        if (proxyClient instanceof Closeable) {
            try {
                ((Closeable) proxyClient).close();
            } catch (IOException e) {
                log.error("While destroying servlet, shutting down HttpClient: " + e, e);
            }
        } else {
            // Older releases require we do this:
            if (proxyClient != null)
                proxyClient.getConnectionManager().shutdown();
        }
        super.destroy();
    }

    @Override
    protected void service(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws ServletException, IOException {
        // Make the Request note: we won't transfer the protocol version because I'm not sure it
        // would truly be compatible
        String method = servletRequest.getMethod();
        String proxyRequestUri = this.rewriteUrlFromRequest(servletRequest);
        HttpRequest proxyRequest;

        // spec: RFC 2616, sec 4.3: either of these two headers signal that
        // there is a message body.
        if (servletRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null
                || servletRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null) {
            proxyRequest = this.newProxyRequestWithEntity(method, proxyRequestUri, servletRequest);
        } else {
            proxyRequest = new BasicHttpRequest(method, proxyRequestUri);
        }

        this.copyRequestHeaders(servletRequest, proxyRequest);

        this.setXForwardedForHeader(servletRequest, proxyRequest);

        HttpResponse proxyResponse = null;
        try {
            // Execute the request
            proxyResponse = this.doExecute(servletRequest, servletResponse, proxyRequest);

            // Process the response:
            // Pass the response code. This method with the "reason phrase" is
            // deprecated but it's the only way to pass the reason along too.
            int statusCode = proxyResponse.getStatusLine().getStatusCode();

            // response logging
            if (doLog)
                log.info("Invoked - {} : {} [ {} ]", proxyRequestUri, method, statusCode);

            // no inspection deprecation
            servletResponse.setStatus(statusCode, proxyResponse.getStatusLine().getReasonPhrase());

            // Copying response headers to make sure SESSIONID or other Cookie
            // which comes from the remote server will be saved in client when 
            // the proxied URL was redirected to another one.
            // See issue
            // [#51](https://github.com/mitre/HTTP-Proxy-Servlet/issues/51)
            this.copyResponseHeaders(proxyResponse, servletRequest, servletResponse);

            if (statusCode == HttpServletResponse.SC_NOT_MODIFIED) {
                // 304 needs special handling. See:
                // http://www.ics.uci.edu/pub/ietf/http/rfc1945.html#Code304
                // Don't send body entity/content!
                servletResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
            } else {
                // Send the content to the client
                this.copyResponseEntity(proxyResponse, servletResponse, proxyRequest, servletRequest);
            }
        } catch (Exception e) {
            // abort request, according to best practice with HttpClient
            if (proxyRequest instanceof AbortableHttpRequest) {
                AbortableHttpRequest abortableHttpRequest = (AbortableHttpRequest) proxyRequest;
                abortableHttpRequest.abort();
            }
            if (e instanceof RuntimeException)
                throw (RuntimeException) e;
            if (e instanceof ServletException)
                throw (ServletException) e;
            // no inspection ConstantConditions
            if (e instanceof IOException)
                throw (IOException) e;
            throw new RuntimeException(e);

        } finally {
            // make sure the entire entity was consumed, so the connection is
            // released
            if (proxyResponse != null)
                this.consumeQuietly(proxyResponse.getEntity());

            // Note: Don't need to close servlet outputStream:
            // http://stackoverflow.com/questions/1159168/should-one-call-close-on-httpservletresponse-getoutputstream-getwriter
        }
    }

    protected HttpResponse doExecute(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
            HttpRequest proxyRequest) throws IOException {
        if (doLog) {
            log.info("Proxy : {}, URI : {} - {}", servletRequest.getMethod(), 
                    servletRequest.getRequestURI(), proxyRequest.getRequestLine().getUri());
        }
        return proxyClient.execute(this.getTargetHost(servletRequest), proxyRequest);
    }

    protected HttpRequest newProxyRequestWithEntity(String method, String proxyRequestUri,
            HttpServletRequest servletRequest) throws IOException {
        HttpEntityEnclosingRequest eProxyRequest = new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);
        // Add the input entity (streamed)
        // note: we don't bother ensuring we close the servletInputStream since
        // the container handles it
        eProxyRequest.setEntity(
                new InputStreamEntity(servletRequest.getInputStream(), getContentLength(servletRequest)));
        return eProxyRequest;
    }

    /**
     * Get the header value as a long in order to more correctly proxy very
     * large requests.
     */
    private long getContentLength(HttpServletRequest request) {
        String contentLengthHeader = request.getHeader("Content-Length");
        if (contentLengthHeader != null) {
            return Long.parseLong(contentLengthHeader);
        }
        return -1L;
    }

    protected void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * HttpClient v4.1 doesn't have the
     * {@link EntityUtils#consumeQuietly(HttpEntity)} method.
     */
    protected void consumeQuietly(HttpEntity entity) {
        try {
            EntityUtils.consume(entity);
        } catch (IOException e) {// ignore
            log.error(e.getMessage(), e);
        }
    }

    /**
     * These are the "hop-by-hop" headers that should not be copied.
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html I use an
     * HttpClient HeaderGroup class instead of Set&lt;String&gt; because this
     * approach does case insensitive lookup faster.
     */
    protected static final HeaderGroup hopByHopHeaders;
    static {
        hopByHopHeaders = new HeaderGroup();
        String[] headers = new String[] {
                "Connection",
                "Keep-Alive",
                "Proxy-Authenticate",
                "Proxy-Authorization",
                "TE",
                "Trailers",
                "Transfer-Encoding",
                "Upgrade" };
        for (String header : headers) {
            hopByHopHeaders.addHeader(new BasicHeader(header, null));
        }
    }

    /**
     * Copy request headers from the servlet client to the proxy request. This
     * is easily overridden to add your own.
     */
    protected void copyRequestHeaders(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
        // Get an Enumeration of all of the header names sent by the client
        Enumeration<String> enumerationOfHeaderNames = servletRequest.getHeaderNames();
        List<String> requestHeaderNames = new ArrayList<>();
        while (enumerationOfHeaderNames.hasMoreElements()) {
            String headerName = enumerationOfHeaderNames.nextElement();
            this.copyRequestHeader(servletRequest, proxyRequest, headerName, requestHeaderNames);
        }

        if (doLog)
            log.info("Request Headers : {}", requestHeaderNames);
    }

    /**
     * Copy a request header from the servlet client to the proxy request. This
     * is easily overridden to filter out certain headers if desired.
     */
    protected void copyRequestHeader(
            HttpServletRequest servletRequest, 
            HttpRequest proxyRequest, 
            String headerName, 
            List<String> finalHeaderNames) {
        // Instead the content-length is effectively set via InputStreamEntity
        if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
            return;
        if (hopByHopHeaders.containsHeader(headerName))
            return;

        // add to final list for debugging purposes
        finalHeaderNames.add(headerName);

        Enumeration<String> headers = servletRequest.getHeaders(headerName);
        while (headers.hasMoreElements()) {// sometimes more than one value
            String headerValue = headers.nextElement();
            // In case the proxy host is running multiple virtual servers,
            // rewrite the Host header to ensure that we get content from
            // the correct virtual server
            if (!preserveHost && headerName.equalsIgnoreCase(HttpHeaders.HOST)) {
                HttpHost host = getTargetHost(servletRequest);
                headerValue = host.getHostName();
                if (host.getPort() != -1)
                    headerValue += ":" + host.getPort();
            } else if (!preserveCookies && headerName.equalsIgnoreCase(org.apache.http.cookie.SM.COOKIE)) {
                headerValue = getRealCookie(headerValue);
            }

            proxyRequest.addHeader(headerName, headerValue);
        }
    }

    private void setXForwardedForHeader(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
        if (forwardIP) {
            String forHeaderName = "X-Forwarded-For";
            String forHeader = servletRequest.getRemoteAddr();
            String existingForHeader = servletRequest.getHeader(forHeaderName);
            if (existingForHeader != null) {
                forHeader = existingForHeader + ", " + forHeader;
            }
            proxyRequest.setHeader(forHeaderName, forHeader);

            String protoHeaderName = "X-Forwarded-Proto";
            String protoHeader = servletRequest.getScheme();
            proxyRequest.setHeader(protoHeaderName, protoHeader);
        }
    }

    /** Copy proxied response headers back to the servlet client. */
    protected void copyResponseHeaders(HttpResponse proxyResponse, HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        List<String> responseHeaderNames = new ArrayList<>();
        for (Header header : proxyResponse.getAllHeaders()) {
            this.copyResponseHeader(servletRequest, servletResponse, header, responseHeaderNames);
        }

        if (doLog)
            log.info("Response Headers : {}", responseHeaderNames);
    }

    /**
     * Copy a proxied response header back to the servlet client. This is easily
     * overwritten to filter out certain headers if desired.
     */
    protected void copyResponseHeader(
            HttpServletRequest servletRequest, 
            HttpServletResponse servletResponse,
            Header header, 
            List<String> finalHeaderNames) {
        String headerName = header.getName();
        if (hopByHopHeaders.containsHeader(headerName))
            return;

        // add to final list for debugging purposes
        finalHeaderNames.add(headerName);

        String headerValue = header.getValue();
        if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE)
                || headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
            this.copyProxyCookie(servletRequest, servletResponse, headerValue);
        } else if (headerName.equalsIgnoreCase(HttpHeaders.LOCATION)) {
            // LOCATION Header may have to be rewritten.
            servletResponse.addHeader(headerName, this.rewriteUrlFromResponse(servletRequest, headerValue));
        } else {
            servletResponse.addHeader(headerName, headerValue);
        }
    }

    /**
     * Copy cookie from the proxy to the servlet client. Replaces cookie path to
     * local path and renames cookie to avoid collisions.
     */
    protected void copyProxyCookie(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
            String headerValue) {
        List<HttpCookie> cookies = HttpCookie.parse(headerValue);

        // path starts with / or is empty string
        String path = servletRequest.getContextPath();

        // servlet path starts with / or is empty string
        path += servletRequest.getServletPath();
        if (path.isEmpty()) {
            path = "/";
        }

        for (HttpCookie cookie : cookies) {
            // set cookie name prefixed w/ a proxy value so it won't collide w/
            // other cookies
            String proxyCookieName = preserveCookies ? cookie.getName()
                    : getCookieNamePrefix(cookie.getName()) + cookie.getName();
            Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
            servletCookie.setComment(cookie.getComment());
            servletCookie.setMaxAge((int) cookie.getMaxAge());
            servletCookie.setPath(path); // set to the path of the proxy servlet
            // don't set cookie domain
            servletCookie.setSecure(cookie.getSecure());
            servletCookie.setVersion(cookie.getVersion());
            servletResponse.addCookie(servletCookie);
        }
    }

    /**
     * Take any client cookies that were originally from the proxy and prepare
     * them to send to the proxy. This relies on cookie headers being set
     * correctly according to RFC 6265 Sec 5.4. This also blocks any local
     * cookies from being sent to the proxy.
     */
    protected String getRealCookie(String cookieValue) {
        StringBuilder escapedCookie = new StringBuilder();
        String cookies[] = cookieValue.split("[;,]");
        for (String cookie : cookies) {
            String cookieSplit[] = cookie.split("=");
            if (cookieSplit.length == 2) {
                String cookieName = cookieSplit[0].trim();
                if (cookieName.startsWith(this.getCookieNamePrefix(cookieName))) {
                    cookieName = cookieName.substring(this.getCookieNamePrefix(cookieName).length());
                    if (escapedCookie.length() > 0) {
                        escapedCookie.append("; ");
                    }
                    escapedCookie.append(cookieName).append("=").append(cookieSplit[1].trim());
                }
            }
        }
        return escapedCookie.toString();
    }

    /** The string prefixing rewritten cookies. */
    protected String getCookieNamePrefix(String name) {
        return "!Proxy!" + getServletConfig().getServletName();
    }

    /**
     * Copy response body data (the entity) from the proxy to the servlet
     * client.
     */
    protected void copyResponseEntity(HttpResponse proxyResponse, HttpServletResponse servletResponse,
            HttpRequest proxyRequest, HttpServletRequest servletRequest) throws IOException {
        HttpEntity entity = proxyResponse.getEntity();
        if (entity != null) {
            OutputStream servletOutputStream = servletResponse.getOutputStream();
            entity.writeTo(servletOutputStream);
        }
    }

    /**
     * Reads the request URI from {@code servletRequest} and rewrites it,
     * considering targetUri. It's used to make the new request.
     */
    protected String rewriteUrlFromRequest(HttpServletRequest servletRequest) {
        StringBuilder uri = new StringBuilder(500);
        uri.append(this.getTargetUri(servletRequest));

        // Handle the path given to the servlet
        // ex: /my/path.html
        /*if (servletRequest.getPathInfo() != null) {
            uri.append(encodeUriQuery(servletRequest.getPathInfo()));
        }*/

        // Handle the query string & fragment
        // ex:(following '?'): name=value&foo=bar#fragment
        String queryString = servletRequest.getQueryString();
        String fragment = null;
        // split off fragment from queryString, updating queryString if found
        if (queryString != null) {
            int fragIdx = queryString.indexOf('#');
            if (fragIdx >= 0) {
                fragment = queryString.substring(fragIdx + 1);
                queryString = queryString.substring(0, fragIdx);
            }
        }

        queryString = this.rewriteQueryStringFromRequest(servletRequest, queryString);
        if (queryString != null && queryString.length() > 0) {
            uri.append('?');
            uri.append(encodeUriQuery(queryString));
        }

        if (sendUrlFragment && fragment != null) {
            uri.append('#');
            uri.append(encodeUriQuery(fragment));
        }
        return uri.toString();
    }

    protected String rewriteQueryStringFromRequest(HttpServletRequest servletRequest, String queryString) {
        return queryString;
    }

    /**
     * For a redirect response from the target server, this translates
     * {@code theUrl} to redirect to and translates it to one the original
     * client can use.
     */
    protected String rewriteUrlFromResponse(HttpServletRequest servletRequest, String theUrl) {
        final String targetUri = getBaseUri(servletRequest);
        if (theUrl.startsWith(targetUri)) {
            /*-
             * The URL points back to the back-end server.
             * Instead of returning it verbatim we replace the target path with our
             * source path in a way that should instruct the original client to
             * request the URL pointed through this Proxy.
             * We do this by taking the current request and rewriting the path part
             * using this servlet's absolute path and the path from the returned URL
             * after the base target URL.
             */
            StringBuffer curUrl = servletRequest.getRequestURL();// no query
            int pos;
            // Skip the protocol part
            if ((pos = curUrl.indexOf("://")) >= 0) {
                // Skip the authority part
                // + 3 to skip the separator between protocol and authority
                if ((pos = curUrl.indexOf("/", pos + 3)) >= 0) {
                    // Trim everything after the authority part.
                    curUrl.setLength(pos);
                }
            }

            // Context path starts with a / if it is not blank
            curUrl.append(servletRequest.getContextPath());

            // Servlet path starts with a / if it is not blank
            curUrl.append(servletRequest.getServletPath());
            curUrl.append(theUrl, targetUri.length(), theUrl.length());
            theUrl = curUrl.toString();
        }
        return theUrl;
    }

    /**
     * Encodes characters in the query or fragment part of the URI.
     *
     * <p>
     * Unfortunately, an incoming URI sometimes has characters disallowed by the
     * spec. HttpClient insists that the outgoing proxied request has a valid
     * URI because it uses Java's {@link URI}. To be more forgiving, we must
     * escape the problematic characters. See the URI class for the spec.
     *
     * @param in
     *            example: name=value&amp;foo=bar#fragment
     */
    protected static CharSequence encodeUriQuery(CharSequence in) {
        // Note that I can't simply use URI.java to encode because it will
        // escape pre-existing escaped things.
        StringBuilder outBuf = null;
        Formatter formatter = null;
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            boolean escape = true;
            if (c < 128) {
                if (asciiQueryChars.get((int) c)) {
                    escape = false;
                }
            } else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {// not-ascii
                escape = false;
            }
            if (!escape) {
                if (outBuf != null)
                    outBuf.append(c);
            } else {
                // escape
                if (outBuf == null) {
                    outBuf = new StringBuilder(in.length() + 5 * 3);
                    outBuf.append(in, 0, i);
                    formatter = new Formatter(outBuf);
                }
                // leading %, 0 padded, width 2, capital hex
                formatter.format("%%%02X", (int) c);// TODO
            }
        }
        return outBuf != null ? outBuf : in;
    }

    protected static final BitSet asciiQueryChars;
    static {
        char[] c_unreserved = "_-!.~'()*".toCharArray();// plus alphanum
        char[] c_punct = ",;:$&+=".toCharArray();
        char[] c_reserved = "?/[]@".toCharArray();// plus punct

        asciiQueryChars = new BitSet(128);
        for (char c = 'a'; c <= 'z'; c++)
            asciiQueryChars.set((int) c);
        for (char c = 'A'; c <= 'Z'; c++)
            asciiQueryChars.set((int) c);
        for (char c = '0'; c <= '9'; c++)
            asciiQueryChars.set((int) c);
        for (char c : c_unreserved)
            asciiQueryChars.set((int) c);
        for (char c : c_punct)
            asciiQueryChars.set((int) c);
        for (char c : c_reserved)
            asciiQueryChars.set((int) c);

        // leave existing percent escapes in place
        asciiQueryChars.set((int) '%');
    }

    /**
     * A boolean parameter name to enable logging of input and target URLs to
     * the servlet log.
     * 
     * @param doLog
     *            the doLog to set
     */
    public void setLog(boolean doLog) {
        this.doLog = doLog;
    }

    /**
     * A boolean parameter name to enable forwarding of the client IP.
     * 
     * @param forwardIP
     *            the doForwardIP to set
     */
    public void setForwardIP(boolean forwardIP) {
        this.forwardIP = forwardIP;
    }

    /**
     * User agents shouldn't send the URL fragment but what if it does?
     * 
     * @param sendUrlFragment
     *            the doSendUrlFragment to set
     */
    public void setSendUrlFragment(boolean sendUrlFragment) {
        this.sendUrlFragment = sendUrlFragment;
    }

    /**
     * A boolean parameter name to keep HOST parameter as-is.
     * 
     * @param preserveHost
     *            the doPreserveHost to set
     */
    public void setPreserveHost(boolean preserveHost) {
        this.preserveHost = preserveHost;
    }

    /**
     * A boolean parameter name to keep COOKIES as-is.
     * 
     * @param preserveCookies
     *            the doPreserveCookies to set
     */
    public void setPreserveCookies(boolean preserveCookies) {
        this.preserveCookies = preserveCookies;
    }

    /**
     * A boolean parameter name to have auto-handle redirects.
     * 
     * @param handleRedirects
     *            the doHandleRedirects to set
     */
    public void setHandleRedirects(boolean handleRedirects) {
        this.handleRedirects = handleRedirects;
    }

    /**
     * An integer parameter name to set the socket connection timeout (millis).
     * 
     * @param connectTimeout
     *            the connectTimeout to set
     */
    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * An integer parameter name to set the socket read timeout (millis).
     * 
     * @param readTimeout
     *            the readTimeout to set
     */
    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }
}
