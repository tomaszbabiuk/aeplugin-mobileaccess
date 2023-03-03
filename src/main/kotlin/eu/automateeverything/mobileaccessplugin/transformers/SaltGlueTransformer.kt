package eu.automateeverything.mobileaccessplugin.transformers

import kotlinx.coroutines.*
import saltchannel.ByteChannel
import saltchannel.util.Bytes
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

class SaltGlueTransformer(
    private val transformed: ByteChannel,
    private val scope: CoroutineScope,
) : ByteChannel {

    companion object {
        const val SALT_HEADER_SIZE = 4
    }

    private var readBuffer: MutableList<Byte> = ArrayList()
    private var allBuffer: MutableList<Byte> = ArrayList()
    private val readQueue : BlockingQueue<ByteArray> = LinkedBlockingQueue()

    init {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                val payload = transformed.read()
                gluePayload(payload)
            }
        }
    }

    override fun read(): ByteArray {
        while (scope.isActive && readQueue.isEmpty()) {
            //wait for packet
        }

        if (!readQueue.isEmpty()) {
            return readQueue.poll()
        }

        throw SessionClosedException()
    }

    private fun gluePayload(payload: ByteArray) {
        allBuffer.addAll(payload.toList())
        readBuffer.addAll(payload.toList())
        if (readBuffer.size > SALT_HEADER_SIZE) {

            val expectedLength = Bytes.bytesToIntLE(byteArrayOf(readBuffer[0], readBuffer[1], 0x00, 0x00), 0)

            if (readBuffer.size >= expectedLength + SALT_HEADER_SIZE) {
                val toSaltChannel = readBuffer.drop(SALT_HEADER_SIZE).take(expectedLength).toByteArray()
                (0 until expectedLength + SALT_HEADER_SIZE).forEach {
                    readBuffer.removeAt(0)
                }
                readQueue.offer(toSaltChannel)
            }
        }
    }

    @Deprecated("Deprecated in Java", ReplaceWith("write(isLast = false, messages = messages)"))
    override fun write(vararg messages: ByteArray) {
        write(isLast = false, messages = messages)
    }

    override fun write(isLast: Boolean, vararg messages: ByteArray) {
        messages.forEach {
            val sizeBytes = ByteArray(SALT_HEADER_SIZE)
            Bytes.intToBytesLE(it.size, sizeBytes, 0)
            val data = sizeBytes + it
            transformed.write(isLast, data)
        }
    }
}