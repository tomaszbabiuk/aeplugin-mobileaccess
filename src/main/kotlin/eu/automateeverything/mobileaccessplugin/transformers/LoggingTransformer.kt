package eu.automateeverything.mobileaccessplugin.transformers

import saltchannel.ByteChannel


open class LoggingTransformer(
    private val transformed: ByteChannel,
    private val prefix: String,
    private val logFunction: (String) -> (Unit),
) : ByteChannel {

    override fun read(): ByteArray {
        val data = transformed.read()
        logFunction("$prefix, IN [${data.size}]: ${data.toHexString()}")
        return data
    }

    @Deprecated("Deprecated in Java", ReplaceWith("write(isLast = false, messages = messages)"))
    override fun write(vararg messages: ByteArray) {
        write(isLast = false, messages = messages)
    }

    override fun write(isLast: Boolean, vararg messages: ByteArray) {
        messages.forEach { data ->
            logFunction("$prefix, OUT [${data.size}]: ${data.toHexString()}")
            transformed.write(isLast, data)
        }
    }
}

fun ByteArray.toHexString() = joinToString(" ") { "%02X".format(it) }