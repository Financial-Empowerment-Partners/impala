package com.payala.impala.stellar

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URISyntaxException
import java.net.URL
import java.net.URLEncoder

/**
 * The three HTTP exchanges of a SEP-10 sign-in. Each returns the response body
 * of a 2xx answer; any other status is a [Sep10HttpException]; transport
 * failures are [IOException]s.
 */
interface Sep10Transport {
    /** GET `<scheme>://<homeDomain>/.well-known/stellar.toml`. */
    @Throws(IOException::class)
    fun fetchToml(homeDomain: String): String

    /** GET `<webAuthEndpoint>?account=<account>&home_domain=<homeDomain>`: the challenge JSON. */
    @Throws(IOException::class)
    fun getChallenge(webAuthEndpoint: String, account: String, homeDomain: String): String

    /** POST `{"transaction": "<transaction>"}` to [webAuthEndpoint]: the token JSON. */
    @Throws(IOException::class)
    fun postChallenge(webAuthEndpoint: String, transaction: String): String
}

/**
 * A non-2xx answer (redirects included: they are never followed). [status] is
 * the HTTP status; [bodyExcerpt] is at most [EXCERPT_LENGTH] printable
 * characters of the body, for display and diagnostics.
 */
class Sep10HttpException(val status: Int, val bodyExcerpt: String) : IOException("HTTP $status") {
    companion object {
        const val EXCERPT_LENGTH = 200

        internal fun excerpt(body: String): String =
            body.take(EXCERPT_LENGTH).map { if (it < ' ' || it == '\u007F') ' ' else it }.joinToString("")
    }
}

/** The scheme rule: https everywhere, http only for the local development hosts. */
object Sep10Urls {
    /** Hosts that may be reached over plain http: the machine itself and the Android emulator's host alias. */
    @JvmField
    val LOCAL_HOSTS: Set<String> = setOf("localhost", "127.0.0.1", "10.0.2.2")

    private val HOME_DOMAIN = Regex("""^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[1-9][0-9]{0,4})?$""")

    /** True when [homeDomain] is a lowercase host name or IPv4 address, optionally with `:port`. */
    @JvmStatic
    fun isValidHomeDomain(homeDomain: String): Boolean = homeDomain.length <= 59 && HOME_DOMAIN.matches(homeDomain)

    @JvmStatic
    fun isLocalHost(host: String): Boolean = host.lowercase() in LOCAL_HOSTS

    /** The stellar.toml URL for [homeDomain]: http only for a local host. */
    @JvmStatic
    fun tomlUrl(homeDomain: String): String {
        require(isValidHomeDomain(homeDomain)) { "invalid home domain" }
        val host = homeDomain.substringBefore(':')
        return (if (isLocalHost(host)) "http" else "https") + "://" + homeDomain + "/.well-known/stellar.toml"
    }

    /**
     * Parses and checks a web-auth endpoint: absolute http(s), a host, no user
     * info, query or fragment, and http only for a local host. Returns the
     * URI, or throws [IllegalArgumentException].
     */
    @JvmStatic
    fun checkEndpoint(endpoint: String): URI {
        val uri = try {
            URI(endpoint)
        } catch (e: URISyntaxException) {
            throw IllegalArgumentException("web auth endpoint is not a URI", e)
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host
        require(scheme == "https" || scheme == "http") { "web auth endpoint must be http(s)" }
        require(!host.isNullOrEmpty()) { "web auth endpoint has no host" }
        require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) { "web auth endpoint must not carry user info, a query or a fragment" }
        require(scheme == "https" || isLocalHost(host)) { "web auth endpoint must use https (http only for ${LOCAL_HOSTS.joinToString()})" }
        return uri
    }

    /**
     * The `web_auth_domain` a challenge from [endpoint] must carry: the
     * endpoint's host, lowercased, plus `:port` when the URL states a port.
     */
    @JvmStatic
    fun webAuthDomain(endpoint: String): String {
        val uri = checkEndpoint(endpoint)
        return uri.host.lowercase() + (if (uri.port >= 0) ":${uri.port}" else "")
    }
}

/**
 * [Sep10Transport] on [HttpURLConnection]: connect and read timeouts, no
 * redirects, no caches, a response size cap, and the [Sep10Urls] scheme rule
 * checked before any connection is opened. Blocking: call it off the main
 * thread.
 */
class HttpSep10Transport @JvmOverloads constructor(
    private val connectTimeoutMillis: Int = 10_000,
    private val readTimeoutMillis: Int = 10_000,
    private val maxResponseBytes: Int = 16 * 1024,
    private val maxTomlBytes: Int = StellarToml.MAX_LENGTH,
) : Sep10Transport {

    override fun fetchToml(homeDomain: String): String =
        exchange(Sep10Urls.tomlUrl(homeDomain), "GET", null, "text/plain, application/toml, */*", maxTomlBytes)

    override fun getChallenge(webAuthEndpoint: String, account: String, homeDomain: String): String {
        Sep10Urls.checkEndpoint(webAuthEndpoint)
        val url = webAuthEndpoint + "?account=" + URLEncoder.encode(account, "UTF-8") +
            "&home_domain=" + URLEncoder.encode(homeDomain, "UTF-8")
        return exchange(url, "GET", null, "application/json", maxResponseBytes)
    }

    override fun postChallenge(webAuthEndpoint: String, transaction: String): String {
        Sep10Urls.checkEndpoint(webAuthEndpoint)
        val body = "{\"transaction\":" + MiniJson.quote(transaction) + "}"
        return exchange(webAuthEndpoint, "POST", body.toByteArray(Charsets.UTF_8), "application/json", maxResponseBytes)
    }

    private fun exchange(url: String, method: String, body: ByteArray?, accept: String, cap: Int): String {
        val parsed = URL(url)
        // Re-check the final URL: the scheme rule holds for every request, whatever built it.
        require(parsed.protocol == "https" || (parsed.protocol == "http" && Sep10Urls.isLocalHost(parsed.host))) {
            "refusing a non-https request to a non-local host"
        }
        val conn = parsed.openConnection() as HttpURLConnection
        try {
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.connectTimeout = connectTimeoutMillis
            conn.readTimeout = readTimeoutMillis
            conn.requestMethod = method
            conn.setRequestProperty("Accept", accept)
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                // Buffered, not fixed-length streaming: in streaming mode the JDK's
                // HttpURLConnection drops the error body of a 401.
                conn.outputStream.use { it.write(body) }
            }
            val status = conn.responseCode
            if (status !in 200..299) {
                val text = try {
                    conn.errorStream?.let { String(readCapped(it, 4 * 1024, truncate = true), Charsets.UTF_8) } ?: ""
                } catch (_: IOException) {
                    ""
                }
                throw Sep10HttpException(status, Sep10HttpException.excerpt(text))
            }
            val declared = conn.contentLengthLong
            if (declared > cap) throw IOException("response of $declared bytes exceeds the $cap-byte cap")
            return conn.inputStream.use { String(readCapped(it, cap, truncate = false), Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
    }

    private fun readCapped(input: InputStream, cap: Int, truncate: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > cap) {
                if (truncate) { out.write(buf, 0, cap - out.size()); break }
                throw IOException("response exceeds the $cap-byte cap")
            }
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}
