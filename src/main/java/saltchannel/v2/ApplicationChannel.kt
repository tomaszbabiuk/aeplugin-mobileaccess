package saltchannel.v2

import saltchannel.BadPeer
import saltchannel.ByteChannel
import saltchannel.ComException
import saltchannel.util.TimeChecker
import saltchannel.util.TimeKeeper
import saltchannel.v2.packets.*
import java.util.concurrent.LinkedBlockingQueue

/**
 * A message channel for the application layer to use after a successful
 * handshake has been completed.
 *
 * The channel works on top of an underlying byte channel (an EncryptedChannelV2).
 * It adds a small header to the messages (2-bytes header + time).
 * Also, this class decides how to encode application messages
 * using either AppPacket or MultiAppPacket.
 *
 * @author Frans Lundberg
 */
class ApplicationChannel(private val channel: ByteChannel, timeKeeper: TimeKeeper, timeChecker: TimeChecker) :
    ByteChannel {
    private val timeKeeper: TimeKeeper
    private val timeChecker: TimeChecker
    private var bufferedM4: M4Packet? = null
    private val readQ: LinkedBlockingQueue<ByteArray>
    private var readLast = false
    private var encryptedChannel: EncryptedChannelV2? = null

    init {
        encryptedChannel = if (channel is EncryptedChannelV2) {
            channel
        } else {
            null
        }
        this.timeKeeper = timeKeeper
        this.timeChecker = timeChecker
        readQ = LinkedBlockingQueue()
    }

    @Throws(ComException::class)
    override suspend fun read(): ByteArray {
        // Note, APP_PACKET and TYPE_MULTI_APP_PACKET do not contain the
        // lastFlag; it is included in ENCRYPTED_MESSAGE.
        //
        if (readQ.size > 0) {
            return try {
                readQ.take()
            } catch (e: InterruptedException) {
                throw Error("should not happen, size is > 0")
            }
        }
        val bytes = channel.read()
        if (encryptedChannel != null) {
            readLast = encryptedChannel!!.lastFlag()
        }
        val header = PacketHeader(bytes, 0)
        val type = header.type
        val result: ByteArray
        if (type == Packet.TYPE_APP_PACKET) {
            val p = AppPacket.fromBytes(bytes, 0, bytes.size)
            timeChecker.checkTime(p.time)
            result = p.appData
        } else if (type == Packet.TYPE_MULTI_APP_PACKET) {
            val multi = MultiAppPacket.fromBytes(bytes, 0, bytes.size)
            timeChecker.checkTime(multi.time)
            val count = multi.appMessages.size
            result = multi.appMessages[0]
            for (i in 1 until count) {
                readQ.add(multi.appMessages[i])
            }
        } else {
            throw BadPeer(
                "unexpected message type, " + type
                        + ", expected AppPacket or MultiAppPacket"
            )
        }
        return result
    }

    /**
     * Returns the number of remaining application buffered application
     * messages. This is the same as the number of further messages
     * of an MultiAppPacket that are buffered by this implementation.
     */
    fun availableFromMultiAppPacket(): Int {
        return readQ.size
    }

    /**
     * Returns true if the last packet read with read() is the last
     * batch of messages of the application session.
     * If available() returns 0, the last message of the session was read.
     */
    fun lastFlag(): Boolean {
        return readLast
    }

    @Throws(ComException::class)
    override fun write(isLast: Boolean, vararg messages: ByteArray) {
        // 
        // * Adds application header (AppPacket/MultiAppPacket).
        // * Adds (prepends) buffered M4 if needed.
        // * Writes to underlying layer (EncryptedChannelV2).
        //
        // messages:  input application messages
        // messages2: application messages with AppPacket/MultiAppPacket headers.
        // messages3: output messages to EncryptedChannelV2 layer, possible with buffered M4.
        //
        val messages2: Array<ByteArray>
        val messages3: Array<ByteArray>
        val currentTime = timeKeeper.time
        val useMulti = MultiAppPacket.shouldUse(messages)
        if (useMulti) {
            val multi = MultiAppPacket()
            multi.appMessages = messages
            multi.time = currentTime
            val msg0 = ByteArray(multi.size)
            multi.toBytes(msg0, 0)
            messages2 = arrayOf(msg0)
        } else {
            messages2 = Array(messages.size) { i ->
                val p = AppPacket()
                p.appData = messages[i]
                p.time = currentTime
                val msg0 = ByteArray(p.size)
                p.toBytes(msg0, 0)
                msg0
            }
        }
        if (bufferedM4 == null) {
            messages3 = messages2
        } else {
            bufferedM4!!.time = currentTime
            val msg0 = bufferedM4!!.toBytes()
            messages3 = arrayOf(msg0) + messages2
            bufferedM4 = null
        }
        channel.write(isLast, *messages3)
    }

    /**
     * Used by framework to set M4, so M4 can be sent together with
     * first application messages.
     */
    fun setBufferedM4(m4: M4Packet?) {
        bufferedM4 = m4
    }
}