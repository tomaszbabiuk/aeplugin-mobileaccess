package eu.automateeverything.mobileaccessplugin

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import saltchannel.CryptoLib
import saltchannel.util.Rand
import saltchannel.v2.SaltClientSession
import saltchannel.v2.SaltServerSession
import java.security.SecureRandom

class SaltChannelIntegration {

    private val random = Rand { b -> SecureRandom.getInstanceStrong().nextBytes(b) }

    private val serverSignKeyPair = CryptoLib.createSigKeys(random)
    private val serverEncKeyPair = CryptoLib.createEncKeys(random)

    private val clientSignKeyPair = CryptoLib.createSigKeys(random)
    private val clientEncKeyPair = CryptoLib.createEncKeys(random)

    @Test
    fun shouldTerminateTheByteChannelWhenCoroutineDies() {
        assertThrows(ChannelTerminatedException::class.java) {
            val clearChannel = QueuedByteChannel {
                //writing not used in this test
            }

            val server = SaltServerSession(serverSignKeyPair, serverEncKeyPair, clearChannel)

            runBlocking {
                withTimeout(10000) {
                    server.handshake()
                }
            }
        }
    }

    @Test
    fun t2() {
        val clearChannel = QueuedByteChannel {
            //writing not used in this test
        }

        val client = SaltClientSession(clientSignKeyPair, clientEncKeyPair, clearChannel)
        val server = SaltServerSession(serverSignKeyPair, serverEncKeyPair, clearChannel)

    }
}