package eu.automateeverything.mobileaccessplugin

import com.southernstorm.noise.protocol.HandshakeState
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import saltchannel.CryptoLib
import saltchannel.util.KeyPair
import saltchannel.util.Rand
import saltchannel.v2.SaltClientSession
import saltchannel.v2.SaltServerSession
import java.security.SecureRandom

class NoiseIntegration {

    @Test
    fun t1() {
        val handshake = HandshakeState("Noise_XX_25519_ChaChaPoly_BLAKE2s", HandshakeState.INITIATOR)
        val buffer = ByteArray(100)
        handshake.start()
        handshake.writeMessage(buffer, 0, byteArrayOf(0x00, 0x00), 0, 2)
    }
}