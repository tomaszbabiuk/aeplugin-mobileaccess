package saltchannel.v2

import saltaa.BadSignatureException
import saltaa.SaltLibFactory
import saltchannel.BadPeer
import saltchannel.ByteChannel
import saltchannel.CryptoLib
import saltchannel.util.*
import saltchannel.v2.packets.*

/**
 * Client-side implementation of a Salt Channel v2 session.
 * Usage: create object, set or create ephemeral key,
 * call handshake(), get resulting encrypted channel (getChannel())
 * to use by application layer. Use getServerSigKey() to get the server's pubkey.
 * Do not reuse the object for more than one Salt Channel session.
 * Limitation: does not support virtual servers, just one pubkey supported.
 * For debug/inspection: the handshake messages (m1, m2, m3, m4) are stored.
 *
 * @author Frans Lundberg
 */
class SaltClientSession(private val sigKeyPair: KeyPair, private val encKeyPair: KeyPair, private val clearChannel: ByteChannel) {
    private var encryptedChannel: EncryptedChannelV2? = null
    private var timeKeeper: TimeKeeper
    private var timeChecker: TimeChecker
    private var wantedServerSigKey: ByteArray? = null
    private var m1: M1Message? = null
    private var m1Hash: ByteArray? = null
    private var m2: M2Message? = null
    private var m2Hash: ByteArray? = null
    private var m3: M3Packet? = null
    private var m4: M4Packet? = null
    private var tt: TTPacket? = null
    private var appChannel: ApplicationChannel? = null
    private var ticketRequested = false
    private var m2Bytes: ByteArray? = null
    private var m2Header: PacketHeader? = null
    var sessionKey: ByteArray? = null
        private set
    private var ticketData: ClientTicketData? = null // ticket data to use

    /**
     * Returns the newly issued ticket from the server or null
     * if no new ticket was sent from the server.
     */
    var newTicketData: ClientTicketData? = null // new ticket from server
        private set
    private val salt = SaltLibFactory.getLib()
    private var bufferM4 = false

    init {
        timeKeeper = NullTimeKeeper.INSTANCE
        timeChecker = NullTimeChecker.INSTANCE
    }

    fun setWantedServer(wantedServerSigKey: ByteArray) {
        this.wantedServerSigKey = wantedServerSigKey
    }

    fun setBufferM4(bufferM4: Boolean) {
        this.bufferM4 = bufferM4
    }

    /**
     * Set to true to request a resume ticket.
     * NOTE, the resume feature is currently (2017-10-09) *experimental*
     * and not included in the v2 spec.
     */
    fun setTicketRequested(requestTicket: Boolean) {
        ticketRequested = requestTicket
    }

    fun setTicketData(ticketData: ClientTicketData?) {
        this.ticketData = ticketData
    }

    fun setTimeKeeper(timeKeeper: TimeKeeper) {
        this.timeKeeper = timeKeeper
    }

    fun setTimeChecker(timeChecker: TimeChecker) {
        this.timeChecker = timeChecker
    }

    /**
     * @throws saltchannel.v2.NoSuchServer
     * @throws saltchannel.BadPeer
     */
    suspend fun handshake() {
        checkThatEncKeyPairWasSet()
        m1()
        readM2Bytes() // M2 or TT message
        if (m2Header!!.type == Packet.TYPE_ENCRYPTED_MESSAGE) {
            tt1()
            return
        }
        m2()
        createEncryptedChannelForNewSession()
        m3()
        validateSignature1()
        m4()
        tt2()
    }

    val channel: ApplicationChannel
        /**
         * Returns a channel to be used by layer above (application layer).
         * Note, it is recommended that the caller uses the ByteChannel interface
         * if possible rather than the specific ApplicationChannel implementation.
         * The API of the interface is likely more stable.
         *
         * @throws IllegalStateException
         * If the channel is not available, has not been created yet.
         */
        get() = appChannel ?: throw IllegalStateException("this.appChannel == null")
    val serverSigKey: ByteArray
        get() = m3!!.serverSigKey

    /**
     * Creates and writes M1 message.
     */
    private fun m1() {
        m1 = M1Message()
        m1!!.time = timeKeeper.firstTime
        m1!!.clientEncKey = encKeyPair.pub()
        m1!!.serverSigKey = wantedServerSigKey
        m1!!.ticketRequested = ticketRequested
        if (ticketData != null) {
            m1!!.ticket = ticketData!!.ticket
        }
        val m1Bytes = m1!!.toBytes()
        m1Hash = CryptoLib.sha512(m1Bytes)
        clearChannel.write(false, m1Bytes)
        if (ticketData != null) {
            createEncryptedChannelForResumedSession()
        }
    }

    private suspend fun readM2Bytes() {
        m2Bytes = clearChannel.read()
        m2Header = V2Util.parseHeader(m2Bytes)
    }

    /**
     * Handles M2 message.
     *
     * @throws saltchannel.v2.NoSuchServer
     */
    private fun m2() {
        m2 = M2Message.fromBytes(m2Bytes, 0)
        if (m2!!.noSuchServer) {
            throw NoSuchServer()
        }
        if (m2!!.time != 0 && m2!!.time != 1) {
            throw BadPeer("time in m2 was " + m2!!.time + ", should be 0 or 1")
        }
        timeChecker.reportFirstTime(m2!!.time)
        m2Hash = CryptoLib.sha512(m2!!.toBytes())
    }

    private suspend fun m3() {
        m3 = M3Packet.fromBytes(encryptedChannel!!.read(), 0)
        timeChecker.checkTime(m3!!.time)
    }

    private fun m4() {
        m4 = M4Packet()
        m4!!.time = timeKeeper.time
        m4!!.clientSigKey = sigKeyPair.pub()
        m4!!.signature2 = signature2()
        if (bufferM4) {
            appChannel!!.setBufferedM4(m4)
        } else {
            encryptedChannel!!.write(false, m4!!.toBytes())
        }
    }

    /**
     * Reads expected TT message.
     */
    private suspend fun tt1() {
        if (encryptedChannel == null) {
            throw BadPeer("got Packet.TYPE_ENCRYPTED_MESSAGE but not resumed channel exists")
        }
        if (!m1!!.ticketRequested) {
            throw BadPeer("got a ticket, but none was requested")
        }
        encryptedChannel!!.pushback(m2Bytes)
        val bytes = encryptedChannel!!.read()
        val tt = TTPacket.fromBytes(bytes, 0)
        newTicketData = ClientTicketData()
        newTicketData!!.sessionKey = sessionKey
        newTicketData!!.sessionNonce = tt.sessionNonce
        newTicketData!!.ticket = tt.ticket
    }

    /**
     * Reads TT packet from server after 3-way handshake.
     */
    private suspend fun tt2() {
        if (m1!!.ticketRequested && m2!!.resumeSupported) {
            val bytes = encryptedChannel!!.read()
            tt = TTPacket.fromBytes(bytes, 0)
            newTicketData = ClientTicketData()
            newTicketData!!.ticket = tt!!.ticket
            newTicketData!!.sessionKey = sessionKey
            newTicketData!!.sessionNonce = tt!!.sessionNonce
        }
    }

    /**
     * Validates M3/Signature1.
     *
     * @throws saltchannel.BadPeer
     */
    private fun validateSignature1() {
        val signedMessage = V2Util.concat(
            m3!!.signature1, V2Util.SIG1_PREFIX, m1Hash, m2Hash
        )
        try {
            val m = ByteArray(signedMessage.size)
            salt.crypto_sign_open(m, signedMessage, m3!!.serverSigKey)
        } catch (e: BadSignatureException) {
            throw BadPeer("invalid signature")
        }
    }

    /**
     * Computes Signature2.
     */
    private fun signature2(): ByteArray {
        return V2Util.createSignature(sigKeyPair, V2Util.SIG2_PREFIX, m1Hash, m2Hash)
    }

    private fun createEncryptedChannelForNewSession() {
        sessionKey = CryptoLib.computeSharedKey(encKeyPair.sec(), m2!!.serverEncKey)
        encryptedChannel = EncryptedChannelV2(clearChannel, sessionKey!!, EncryptedChannelV2.Role.CLIENT)
        appChannel = ApplicationChannel(encryptedChannel!!, timeKeeper, timeChecker)
    }

    private fun createEncryptedChannelForResumedSession() {
        sessionKey = ticketData!!.sessionKey
        encryptedChannel = EncryptedChannelV2(
            clearChannel, sessionKey!!,
            EncryptedChannelV2.Role.CLIENT, ticketData!!.sessionNonce
        )
        appChannel = ApplicationChannel(encryptedChannel!!, timeKeeper, timeChecker)
    }

    private fun checkThatEncKeyPairWasSet() {
        checkNotNull(encKeyPair) { "encKeyPair must be set before calling handshake()" }
    }
}