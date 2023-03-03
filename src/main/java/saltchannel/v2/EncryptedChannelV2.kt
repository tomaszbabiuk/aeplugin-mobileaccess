package saltchannel.v2

import saltaa.BadEncryptedDataException
import saltaa.SaltLib
import saltaa.SaltLibFactory
import saltchannel.BadPeer
import saltchannel.ByteChannel
import saltchannel.ComException
import saltchannel.util.Bytes
import saltchannel.v2.packets.EncryptedMessage
import saltchannel.v2.packets.TTPacket
import java.util.*

/**
 * An implementation of an encrypted channel using a shared symmetric
 * session key.
 * The read/write methods throws ComException for low-level IO errors
 * and BadPeer if the data format is not OK including cases when the data
 * is not encrypted correctly (when authentication of encrypted data fails).
 *
 * @author Frans Lundberg
 */
class EncryptedChannelV2 @JvmOverloads constructor(
    channel: ByteChannel,
    key: ByteArray,
    role: Role?,
    sessionNonce: ByteArray = zeroSessionNonce()
) : ByteChannel {
    private var readNonceInteger: Long = 0
    private val readNonceBytes = ByteArray(SaltLib.crypto_box_NONCEBYTES)
    private var writeNonceInteger: Long = 0
    private val writeNonceBytes = ByteArray(SaltLib.crypto_box_NONCEBYTES)
    private val key: ByteArray
    private val channel: ByteChannel
    private var pushbackMessage: ByteArray? = null
    private val sessionNonce: ByteArray
    private var lastReadEncryptedPacket: EncryptedMessage? = null
    private val salt = SaltLibFactory.getLib()

    /**
     * Creates a new EncryptedChannel given the underlying channel to be
     * encrypted, the key and the role of the peer (client or server).
     *
     * @param key
     * Shared symmetric encryption key for one session.
     * A new key must be used for every session.
     */
    init {
        require(key.size == SaltLib.crypto_box_SECRETKEYBYTES) { "bad key size, should be " + SaltLib.crypto_box_SECRETKEYBYTES }
        this.channel = channel
        this.key = key
        this.sessionNonce = sessionNonce
        when (role) {
            Role.CLIENT -> {
                setWriteNonce(1)
                setReadNonce(2)
            }

            Role.SERVER -> {
                setWriteNonce(2)
                setReadNonce(1)
            }

            else -> throw Error("never happens")
        }
    }

    /**
     * Role of this peer of the encrypted channel.
     * Used for nonce handling.
     */
    enum class Role {
        CLIENT, SERVER
    }

    fun pushback(pushbackMessage: ByteArray?) {
        this.pushbackMessage = pushbackMessage
    }

    @Throws(ComException::class, BadPeer::class)
    override suspend fun read(): ByteArray {
        val message = readOrTakePushback()
        lastReadEncryptedPacket = unwrap(message)
        val encrypted = lastReadEncryptedPacket!!.body
        val clear = decrypt(encrypted)
        increaseReadNonce()
        return clear
    }

    /**
     * Returns the lastFlag of the last read packet.
     */
    fun lastFlag(): Boolean {
        return if (lastReadEncryptedPacket == null) false else lastReadEncryptedPacket!!.lastFlag()
    }

    private suspend fun readOrTakePushback(): ByteArray? {
        val bytes: ByteArray?
        if (pushbackMessage != null) {
            bytes = pushbackMessage
            pushbackMessage = null
        } else {
            bytes = channel.read()
        }
        return bytes
    }

    /**
     * Takes cleartext messages, encrypts them, and writes them to underlying
     * channel.
     */
    @Throws(ComException::class, BadPeer::class)
    override fun write(isLast: Boolean, vararg messages: ByteArray) {
        val toWrite = Array(messages.size) { i ->
            val encrypted = encrypt(messages[i])
            val msg0 = wrap(isLast && i == messages.size - 1, encrypted)
            increaseWriteNonce()
            msg0
        }

        channel.write(isLast, *toWrite)
    }

    /**
     * @throws saltchannel.ComException
     * @throws saltchannel.BadPeer
     */
    private fun decrypt(encrypted: ByteArray?): ByteArray {
        if (encrypted == null) {
            throw Error("encrypted == null")
        }
        val clear: ByteArray
        val c = ByteArray(SaltLib.crypto_secretbox_OVERHEAD_BYTES + encrypted.size)
        val m = ByteArray(c.size)
        System.arraycopy(encrypted, 0, c, SaltLib.crypto_secretbox_OVERHEAD_BYTES, encrypted.size)
        if (c.size < 32) {
            throw BadPeer("ciphertext too small")
        }
        try {
            salt.crypto_box_open_afternm(m, c, readNonceBytes, key)
        } catch (e: BadEncryptedDataException) {
            throw BadPeer("invalid encryption, could not be decrypted")
        }
        clear = m.copyOfRange(SaltLib.crypto_secretbox_INTERNAL_OVERHEAD_BYTES, m.size)
        return clear
    }

    /**
     * Needed by ServerChannelV2.
     */
    fun encryptAndIncreaseWriteNonce(isLast: Boolean, bytes: ByteArray): ByteArray {
        val encrypted = wrap(isLast, encrypt(bytes))
        increaseWriteNonce()
        return encrypted
    }

    private fun encrypt(clear: ByteArray): ByteArray {
        val m = ByteArray(SaltLib.crypto_secretbox_INTERNAL_OVERHEAD_BYTES + clear.size)
        val c = ByteArray(m.size)
        System.arraycopy(clear, 0, m, SaltLib.crypto_secretbox_INTERNAL_OVERHEAD_BYTES, clear.size)
        salt.crypto_box_afternm(c, m, writeNonceBytes, key)
        return c.copyOfRange(SaltLib.crypto_secretbox_OVERHEAD_BYTES, c.size)
    }

    private fun setWriteNonce(nonceInteger: Long) {
        writeNonceInteger = nonceInteger
        updateWriteNonceBytes()
    }

    /**
     * Not private intentionally. Used by ServerChannel.
     */
    private fun increaseWriteNonce() {
        // Since we will never in practice have overflow of writeNonceInteget an Error is thrown.
        if (writeNonceInteger > Long.MAX_VALUE - 2) {
            throw Error("writeNonce too big")
        }
        setWriteNonce(writeNonceInteger + 2)
    }

    private fun setReadNonce(nonceInteger: Long) {
        readNonceInteger = nonceInteger
        updateReadNonceBytes()
    }

    private fun increaseReadNonce() {
        // Since we will never in practice have overflow of readNonceInteger an Error is thrown.
        if (readNonceInteger > Long.MAX_VALUE - 2) {
            throw Error("readNonce too big")
        }
        setReadNonce(readNonceInteger + 2)
    }

    private fun updateReadNonceBytes() {
        Bytes.longToBytesLE(readNonceInteger, readNonceBytes, 0)
        System.arraycopy(sessionNonce, 0, readNonceBytes, 8, TTPacket.SESSION_NONCE_SIZE)
    }

    private fun updateWriteNonceBytes() {
        Bytes.longToBytesLE(writeNonceInteger, writeNonceBytes, 0)
        System.arraycopy(sessionNonce, 0, writeNonceBytes, 8, TTPacket.SESSION_NONCE_SIZE)
    }

    companion object {
        private fun zeroSessionNonce(): ByteArray {
            return ByteArray(TTPacket.SESSION_NONCE_SIZE)
        }

        /**
         * Wrap encrypted bytes in EncryptedPacket.
         */
        fun wrap(isLast: Boolean, bytes: ByteArray?): ByteArray {
            val p = EncryptedMessage()
            p.body = bytes
            p.lastFlag = isLast
            val result = ByteArray(p.size)
            p.toBytes(result, 0)
            return result
        }

        fun unwrapToBytes(packetBytes: ByteArray?): ByteArray {
            val p = unwrap(packetBytes)
            return p.body
        }

        fun unwrap(packetBytes: ByteArray?): EncryptedMessage {
            return EncryptedMessage.fromBytes(packetBytes, 0, packetBytes!!.size)
        }
    }
}