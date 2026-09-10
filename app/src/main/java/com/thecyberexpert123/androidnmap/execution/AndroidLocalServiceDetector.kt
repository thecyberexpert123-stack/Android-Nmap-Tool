package com.thecyberexpert123.androidnmap.execution

import android.net.Network
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.math.max
import kotlin.math.min

private val bannerFirstPorts = setOf(21, 22, 23, 25, 110, 143, 587)
private val httpLikePorts = setOf(
    80, 81, 82, 83, 84, 85, 88, 3000, 3128, 5000, 5601, 5984,
    7001, 8000, 8008, 8080, 8081, 8088, 8090, 8091, 8200, 8888,
    9000, 9090, 9200, 9999, 10000, 15672, 27017, 28017,
)
private val tlsLikePorts = setOf(443, 444, 465, 636, 993, 995, 2376, 2484, 5061, 6443, 8443)
private val httpsLikePorts = setOf(443, 444, 2376, 6443, 8443)

internal data class AndroidLocalDetectedService(
    val port: Int,
    val serviceName: String,
    val details: String = "",
)

internal data class AndroidLocalServiceDetectionBatch(
    val findingsByPort: Map<Int, AndroidLocalDetectedService>,
    val attemptedCount: Int,
    val skippedCount: Int,
    val warnings: List<String> = emptyList(),
)

internal object AndroidLocalServiceDetector {
    private val tlsSocketFactory: SSLSocketFactory by lazy {
        val trustAllManagers = arrayOf<TrustManager>(
            object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit

                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            },
        )
        SSLContext.getInstance("TLS").apply {
            init(null, trustAllManagers, SecureRandom())
        }.socketFactory
    }

    suspend fun detectOpenTcpServices(
        network: Network,
        targetLabel: String,
        targetAddress: InetAddress,
        openPorts: List<Int>,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
        maxConcurrency: Int,
        maxDetections: Int,
    ): AndroidLocalServiceDetectionBatch = withContext(Dispatchers.IO) {
        if (openPorts.isEmpty()) {
            return@withContext AndroidLocalServiceDetectionBatch(
                findingsByPort = emptyMap(),
                attemptedCount = 0,
                skippedCount = 0,
            )
        }
        val portsToDetect = openPorts.distinct().sorted().take(maxDetections.coerceAtLeast(0))
        val semaphore = Semaphore(max(1, min(maxConcurrency, 4)))
        val findings = coroutineScope {
            portsToDetect.map { port ->
                async(Dispatchers.IO) {
                    semaphore.acquire()
                    try {
                        detectSingleService(
                            network = network,
                            targetLabel = targetLabel,
                            targetAddress = targetAddress,
                            port = port,
                            connectTimeoutMillis = connectTimeoutMillis,
                            readTimeoutMillis = readTimeoutMillis,
                        )
                    } finally {
                        semaphore.release()
                    }
                }
            }.awaitAll()
        }.filterNotNull()
        val skippedCount = (openPorts.distinct().size - portsToDetect.size).coerceAtLeast(0)
        AndroidLocalServiceDetectionBatch(
            findingsByPort = findings.associateBy { it.port },
            attemptedCount = portsToDetect.size,
            skippedCount = skippedCount,
            warnings = buildList {
                if (skippedCount > 0) {
                    add(
                        "Curated Android-local service detection skipped $skippedCount open endpoint(s) after reaching the per-run limit of $maxDetections.",
                    )
                }
            },
        )
    }

    private fun detectSingleService(
        network: Network,
        targetLabel: String,
        targetAddress: InetAddress,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): AndroidLocalDetectedService? {
        val sanitizedTargetLabel = targetLabel.trim().removePrefix("[").removeSuffix("]").ifBlank {
            targetAddress.hostAddress.orEmpty().ifBlank { "target" }
        }

        val passiveBanner = if (port in bannerFirstPorts) {
            probePassiveBanner(network, targetAddress, port, connectTimeoutMillis, readTimeoutMillis)
        } else {
            null
        }
        passiveBanner?.let { return it }
        if (port in tlsLikePorts) {
            probeTlsService(
                network = network,
                targetLabel = sanitizedTargetLabel,
                targetAddress = targetAddress,
                port = port,
                connectTimeoutMillis = connectTimeoutMillis,
                readTimeoutMillis = readTimeoutMillis,
            )?.let { return it }
        }
        if (port in httpLikePorts) {
            probeHttpService(network, sanitizedTargetLabel, targetAddress, port, connectTimeoutMillis, readTimeoutMillis)?.let { return it }
        }
        return passiveBanner ?: probePassiveBanner(network, targetAddress, port, connectTimeoutMillis, readTimeoutMillis)
    }

    private fun probePassiveBanner(
        network: Network,
        targetAddress: InetAddress,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): AndroidLocalDetectedService? {
        val socket = network.socketFactory.createSocket() as Socket
        return try {
            socket.soTimeout = min(readTimeoutMillis, 1_200)
            socket.connect(InetSocketAddress(targetAddress, port), connectTimeoutMillis)
            val buffer = ByteArray(512)
            val bytesRead = socket.getInputStream().read(buffer)
            if (bytesRead <= 0) {
                null
            } else {
                val banner = sanitizePreviewText(String(buffer, 0, bytesRead, Charsets.UTF_8))
                    .lineSequence()
                    .map(String::trim)
                    .firstOrNull(String::isNotBlank)
                    ?.take(200)
                    ?: return null
                val fallback = defaultServiceName(port)
                when {
                    banner.startsWith("SSH-", ignoreCase = true) -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = "ssh",
                        details = "android-local sV: banner $banner",
                    )
                    banner.startsWith("HTTP/", ignoreCase = true) -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = if (port in tlsLikePorts) "https" else "http",
                        details = "android-local sV: $banner",
                    )
                    banner.startsWith("+OK", ignoreCase = true) -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = if (port == 995) "pop3s" else "pop3",
                        details = "android-local sV: banner $banner",
                    )
                    banner.startsWith("* OK", ignoreCase = true) -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = if (port == 993) "imaps" else "imap",
                        details = "android-local sV: banner $banner",
                    )
                    banner.startsWith("220", ignoreCase = true) && port == 21 -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = "ftp",
                        details = "android-local sV: banner $banner",
                    )
                    banner.startsWith("220", ignoreCase = true) && port in setOf(25, 465, 587) -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = if (port == 465) "smtps" else if (port == 587) "submission" else "smtp",
                        details = "android-local sV: banner $banner",
                    )
                    else -> AndroidLocalDetectedService(
                        port = port,
                        serviceName = fallback,
                        details = "android-local sV: banner $banner",
                    )
                }
            }
        } catch (_: SocketTimeoutException) {
            null
        } catch (_: Exception) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun probeHttpService(
        network: Network,
        targetLabel: String,
        targetAddress: InetAddress,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): AndroidLocalDetectedService? {
        val socket = network.socketFactory.createSocket() as Socket
        return try {
            socket.soTimeout = readTimeoutMillis
            socket.connect(InetSocketAddress(targetAddress, port), connectTimeoutMillis)
            socket.getOutputStream().write(
                (
                    "HEAD / HTTP/1.0\r\n" +
                        "Host: $targetLabel\r\n" +
                        "User-Agent: Android-Nmap-Tool\r\n" +
                        "Connection: close\r\n\r\n"
                    ).toByteArray(Charsets.UTF_8),
            )
            socket.getOutputStream().flush()
            val lines = socket.getInputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                readResponsePreview(reader)
            }
            val statusLine = lines.firstOrNull { it.startsWith("HTTP/", ignoreCase = true) } ?: return null
            val serverHeader = lines.firstOrNull { it.startsWith("Server:", ignoreCase = true) }
                ?.substringAfter(':')
                ?.trim()
                ?.takeIf(String::isNotBlank)
            val details = buildList {
                add(statusLine.take(120))
                serverHeader?.let { add("Server: ${it.take(120)}") }
            }.joinToString(separator = "; ")
            AndroidLocalDetectedService(
                port = port,
                serviceName = if (port in tlsLikePorts) "https" else "http",
                details = "android-local sV: $details",
            )
        } catch (_: Exception) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    private fun probeTlsService(
        network: Network,
        targetLabel: String,
        targetAddress: InetAddress,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): AndroidLocalDetectedService? {
        val baseSocket = network.socketFactory.createSocket() as Socket
        return try {
            baseSocket.connect(InetSocketAddress(targetAddress, port), connectTimeoutMillis)
            val sslSocket = tlsSocketFactory.createSocket(baseSocket, targetLabel, port, true) as SSLSocket
            sslSocket.useClientMode = true
            sslSocket.soTimeout = readTimeoutMillis
            sslSocket.startHandshake()
            val session = sslSocket.session
            val protocol = session.protocol?.takeIf(String::isNotBlank)
            val cipherSuite = session.cipherSuite?.takeIf(String::isNotBlank)
            val peerSubject = runCatching { session.peerPrincipal?.name?.takeIf(String::isNotBlank) }.getOrNull()
            val httpDetails = if (port in httpsLikePorts) {
                probeHttpOverEstablishedTlsSocket(sslSocket, targetLabel)
            } else {
                null
            }
            val serviceName = when {
                httpDetails != null -> "https"
                port == 465 -> "smtps"
                port == 636 -> "ldaps"
                port == 993 -> "imaps"
                port == 995 -> "pop3s"
                port == 5061 -> "sips"
                else -> defaultServiceName(port).ifBlank { "tls" }
            }
            val details = buildList {
                protocol?.let { add("TLS $it") }
                cipherSuite?.let { add("cipher ${it.take(80)}") }
                peerSubject?.let { add("subject ${it.take(120)}") }
                httpDetails?.let { add(it) }
            }.joinToString(separator = "; ")
            AndroidLocalDetectedService(
                port = port,
                serviceName = serviceName,
                details = if (details.isBlank()) "android-local sV: TLS handshake succeeded" else "android-local sV: $details",
            )
        } catch (_: Exception) {
            null
        } finally {
            runCatching { baseSocket.close() }
        }
    }

    private fun probeHttpOverEstablishedTlsSocket(
        sslSocket: SSLSocket,
        targetLabel: String,
    ): String? =
        runCatching {
            sslSocket.getOutputStream().write(
                (
                    "HEAD / HTTP/1.0\r\n" +
                        "Host: $targetLabel\r\n" +
                        "User-Agent: Android-Nmap-Tool\r\n" +
                        "Connection: close\r\n\r\n"
                    ).toByteArray(Charsets.UTF_8),
            )
            sslSocket.getOutputStream().flush()
            val lines = sslSocket.getInputStream().bufferedReader(Charsets.UTF_8).use { reader ->
                readResponsePreview(reader)
            }
            val statusLine = lines.firstOrNull { it.startsWith("HTTP/", ignoreCase = true) }
            if (statusLine == null) {
                null
            } else {
                val serverHeader = lines.firstOrNull { it.startsWith("Server:", ignoreCase = true) }
                    ?.substringAfter(':')
                    ?.trim()
                    ?.takeIf(String::isNotBlank)
                buildList {
                    add(statusLine.take(120))
                    serverHeader?.let { add("Server: ${it.take(120)}") }
                }.joinToString(separator = "; ")
            }
        }.getOrNull()

    private fun sanitizePreviewText(value: String): String = buildString(value.length) {
        value.forEach { character ->
            when {
                character == '\u0000' -> append(' ')
                character == '\n' || character == '\r' || character == '\t' -> append(character)
                java.lang.Character.isISOControl(character) -> append(' ')
                else -> append(character)
            }
        }
    }

    private fun readResponsePreview(reader: java.io.BufferedReader): List<String> {
        val lines = mutableListOf<String>()
        repeat(20) {
            val line = reader.readLine() ?: return lines
            val trimmed = line.trim()
            if (trimmed.isEmpty()) {
                return lines
            }
            lines += trimmed
        }
        return lines
    }

    private fun defaultServiceName(port: Int): String = when (port) {
        21 -> "ftp"
        22 -> "ssh"
        23 -> "telnet"
        25 -> "smtp"
        53 -> "domain"
        80, 81, 82, 83, 84, 85, 88, 3000, 3128, 5000, 5601, 5984,
        7001, 8000, 8008, 8080, 8081, 8088, 8090, 8091, 8200, 8888,
        9000, 9090, 9200, 9999, 10000, 15672, 27017, 28017 -> "http"
        110 -> "pop3"
        111 -> "rpcbind"
        143 -> "imap"
        389 -> "ldap"
        443, 444, 2376, 6443, 8443 -> "https"
        445 -> "microsoft-ds"
        465 -> "smtps"
        587 -> "submission"
        636 -> "ldaps"
        993 -> "imaps"
        995 -> "pop3s"
        3306 -> "mysql"
        3389 -> "ms-wbt-server"
        5061 -> "sips"
        5432 -> "postgresql"
        5672 -> "amqp"
        5900 -> "vnc"
        6379 -> "redis"
        9092 -> "kafka"
        9300 -> "elasticsearch-node"
        11211 -> "memcached"
        else -> "unknown"
    }
}
