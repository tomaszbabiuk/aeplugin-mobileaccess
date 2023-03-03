package saltchannel.v2

import saltaa.BadSignatureException
import saltaa.SaltLibFactory
import saltchannel.BadPeer
import saltchannel.ByteChannel
import saltchannel.CryptoLib
import saltchannel.a1a2.A1Packet
import saltchannel.a1a2.A2Packet
import saltchannel.a1a2.A2Packet.Prot
import saltchannel.util.*
import saltchannel.v2.packets.*
import java.util.*


/**
 * Server-side implementation of a Salt Channel v2 session.
 * Usage: create object, set or create ephemeral key, use other setX methods,
 * call handshake(), get resulting encrypted ByteChannel to use by
 * application layer. Use getClientSig() to get client's pubkey.
 * Do not reuse the object for more than one Salt Channel session.
 * Limitation: does not support virtual servers, just one pubkey supported.
 *
 * @author Frans Lundberg
 */
class SaltServerSession(private val sigKeyPair: KeyPair, private val encKeyPair: KeyPair,  private val clearChannel: ByteChannel) {
    private var encryptedChannel: EncryptedChannelV2? = null
    private var timeKeeper: TimeKeeper
    private var timeChecker: TimeChecker
    private var a2Packet: A2Packet? = null
    private var m1: M1Message? = null
    private var m1Hash: ByteArray? = null
    private var m2: M2Message? = null
    private var m2Hash: ByteArray? = null
    private var m4: M4Packet? = null
    private var appChannel: ApplicationChannel? = null
    private var resumeHandler: ResumeHandler? = null
    private var m1Bytes: ByteArray? = null
    private var m1Header: PacketHeader? = null
    private var sessionKey: ByteArray? = null

    /**
     * Returns the static (signing) public key of the client.
     * Available after a successful handshake.
     */
    var clientSigKey: ByteArray? = null
        private set

    private val salt = SaltLibFactory.getLib()
    private var bufferM2 = false
    /**
     * If the session is complete after handshake() has been called, this
     * method returns true. If so, the consumer must not call getChannel() to
     * receive an application channel.
     */
    /** Set to true in handshake after an A1A2 session.  */
    private var isDone = false

    init {
        timeKeeper = NullTimeKeeper.INSTANCE
        timeChecker = NullTimeChecker.INSTANCE
        initDefaultA2()
    }

    private fun initDefaultA2() {
        a2Packet = A2Packet()
        a2Packet!!.prots = arrayOfNulls(1)
        a2Packet!!.prots[0] = Prot(A2Packet.SC2_PROT_STRING, "----------")
    }

    fun setA2(a2Packet: A2Packet?) {
        this.a2Packet = a2Packet
    }

    fun setTimeKeeper(timeKeeper: TimeKeeper) {
        this.timeKeeper = timeKeeper
    }

    fun setTimeChecker(timeChecker: TimeChecker) {
        this.timeChecker = timeChecker
    }

    /**
     * Set to true to buffer M2; that is, M2+M3 will be written together
     * in one write. This is likely more performant when crypto is fast
     * compared to IO. When the peer's crypto computations are slow relative
     * to IO, do not buffer M2.
     */
    fun setBufferM2(bufferM2: Boolean) {
        this.bufferM2 = bufferM2
    }

    fun setResumeHandler(resumeHandler: ResumeHandler?) {
        this.resumeHandler = resumeHandler
    }

    /**
     * Executes the salt channel handshake or returns the A2 packet
     * given an A1 request.
     *
     * @throws saltchannel.v2.NoSuchServer
     * If the client requested to connect to a server given
     * a public key and such a server does not exist.
     * @throws saltchannel.BadPeer
     */
    suspend fun handshake() {
        readM1()
        if (m1Header!!.type == Packet.TYPE_A1) {
            a2()
            isDone = true
            return
        }
        val resumed = processM1()
        if (resumed) {
            return
        }
        m2()
        createEncryptedChannelFromKeyAgreement()
        m3()
        m4()
        validateSignature2()
        tt()
    }

    private suspend fun readM1() {
        m1Bytes = clearChannel.read()
        m1Header = V2Util.parseHeader(m1Bytes)
    }

    private fun checkThatA2WasSet() {
        checkNotNull(a2Packet) { "a2Packet was not set" }
    }

    val channel: ApplicationChannel?
        /**
         * Returns the application channel after a successful handshake.
         * The returned channel is for the application to use.
         * Note, it is recommended that the caller uses the ByteChannel interface
         * if possible rather than the specific ApplicationChannel implementation.
         * The API of the interface is likely more stable.
         *
         * @throws IllegalStateException
         * If the session ended already, due to an A1A2 session.
         */
        get() {
            check(!isDone) { "session is done, no application channel available" }
            return appChannel
        }

    /**
     * Writes the A2 response.
     */
    private fun a2() {
        checkThatA2WasSet()
        var a2 = a2Packet
        val a1 = A1Packet.fromBytes(m1Bytes, 0)
        if (a1.addressType == A1Packet.ADDRESS_TYPE_PUBKEY.toInt()
            && !Arrays.equals(sigKeyPair.pub(), a1.address)
        ) {
            a2 = A2Packet.createNoSuchServerPacket()
        }
        val buffer = ByteArray(a2!!.size)
        a2.toBytes(buffer, 0)
        clearChannel.write(true, buffer) // LastFlag is set.
    }

    /**
     * Returns true if the session was resumed using a ticket in M1.
     *
     * @throws saltchannel.v2.NoSuchServer
     */
    private fun processM1(): Boolean {
        // Note the missing support for "virtual hosting". 
        // Only one server sig key is allowed here.
        m1Hash = CryptoLib.sha512(m1Bytes)
        m1 = M1Message.fromBytes(m1Bytes, 0)!!
        if (m1!!.time != 0 && m1!!.time != 1) {
            throw BadPeer("time in m1 was " + m1!!.time + ", must be 0 or 1")
        }
        timeChecker.reportFirstTime(m1!!.time)
        if (m1!!.serverSigKeyIncluded() && !Arrays.equals(sigKeyPair.pub(), m1!!.serverSigKey)) {
            clearChannel.write(true, noSuchServerM2Raw()) // LastFlag is set
            throw NoSuchServer()
        }
        if (m1!!.ticketIncluded() && resumeSupported()) {
            val sessionData: TicketSessionData = try {
                resumeHandler!!.validateTicket(m1!!.ticket)
            } catch (e: BadTicket) {
                return false
            }
            createEncryptedChannelFromResumedSession(sessionData)
            writeTTPacket()
            return true
        }
        return false
    }

    private fun m2() {
        m2 = M2Message()
        m2!!.time = timeKeeper.firstTime
        m2!!.noSuchServer = false
        m2!!.serverEncKey = encKeyPair.pub()
        m2!!.resumeSupported = resumeHandler != null
        if (!bufferM2) {
            m2!!.time = timeKeeper.firstTime
            val m2Bytes = m2!!.toBytes()
            m2Hash = CryptoLib.sha512(m2Bytes)
            clearChannel.write(false, m2Bytes)
        }
    }

    private fun m3() {
        val time: Int
        var m2Bytes: ByteArray? = null
        if (bufferM2) {
            time = timeKeeper.firstTime
            m2!!.time = time
            m2Bytes = m2!!.toBytes()
            m2Hash = CryptoLib.sha512(m2Bytes)
        } else {
            time = timeKeeper.time
        }
        val p = M3Packet()
        p.time = time
        p.serverSigKey = sigKeyPair.pub()
        p.signature1 = signature1()
        val m3Bytes = p.toBytes()
        val m3Encrypted = encryptedChannel!!.encryptAndIncreaseWriteNonce(false, m3Bytes)
        if (bufferM2) {
            clearChannel.write(false, m2Bytes!!, m3Encrypted)
        } else {
            clearChannel.write(false, m3Encrypted)
        }
    }

    private suspend fun m4() {
        m4 = M4Packet.fromBytes(encryptedChannel!!.read(), 0)
        timeChecker.checkTime(m4!!.time)
        clientSigKey = m4!!.clientSigKey
    }

    /**
     * Sends TT message if this server supports resume and
     * the client requested a ticket.
     */
    private fun tt() {
        if (!resumeSupported()) {
            return
        }
        if (m1!!.ticketRequested) {
            writeTTPacket()
        }
    }

    private fun writeTTPacket() {
        val t = resumeHandler!!.issueTicket(clientSigKey, sessionKey)
        val p = TTPacket()
        p.time = timeKeeper.time
        p.ticket = t.ticket
        p.sessionNonce = t.sessionNonce
        encryptedChannel!!.write(false, p.toBytes())
    }

    private fun createEncryptedChannelFromKeyAgreement() {
        sessionKey = CryptoLib.computeSharedKey(encKeyPair.sec(), m1!!.clientEncKey)
        encryptedChannel = EncryptedChannelV2(clearChannel, sessionKey!!, EncryptedChannelV2.Role.SERVER)
        appChannel = ApplicationChannel(encryptedChannel!!, timeKeeper, timeChecker)
    }

    /**
     * Creates this.encryptedChannel, this.appChannel,
     * sets this.sessionKey and this.clientSigKey.
     */
    private fun createEncryptedChannelFromResumedSession(data: TicketSessionData) {
        sessionKey = data.sessionKey
        clientSigKey = data.clientSigKey
        encryptedChannel = EncryptedChannelV2(
            clearChannel, sessionKey!!,
            EncryptedChannelV2.Role.SERVER, data.sessionNonce
        )
        appChannel = ApplicationChannel(encryptedChannel!!, timeKeeper, timeChecker)
    }

    private fun resumeSupported(): Boolean {
        return resumeHandler != null
    }

    /**
     * Computes Signature1.
     */
    private fun signature1(): ByteArray {
        return V2Util.createSignature(sigKeyPair, V2Util.SIG1_PREFIX, m1Hash, m2Hash)
    }

    /**
     * Validates M4/Signature2.
     *
     * @throws saltchannel.BadPeer
     */
    private fun validateSignature2() {
        assert(m4!!.signature2 != null)
        assert(m1!!.clientEncKey != null)
        assert(encKeyPair.pub() != null)
        val signedMessage = V2Util.concat(m4!!.signature2, V2Util.SIG2_PREFIX, m1Hash, m2Hash)
        try {
            val m = ByteArray(signedMessage.size)
            salt.crypto_sign_open(m, signedMessage, m4!!.clientSigKey)
        } catch (e: BadSignatureException) {
            throw BadPeer("invalid signature")
        }
    }

    private fun noSuchServerM2Raw(): ByteArray {
        val m2 = M2Message()
        m2.time = timeKeeper.firstTime
        m2.noSuchServer = true
        m2.lastFlag = true
        m2.serverEncKey = ByteArray(32)
        val raw = ByteArray(m2.size)
        m2.toBytes(raw, 0)
        return raw
    }
}