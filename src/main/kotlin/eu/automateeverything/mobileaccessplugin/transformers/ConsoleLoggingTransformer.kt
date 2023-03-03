package eu.automateeverything.mobileaccessplugin.transformers

import saltchannel.ByteChannel

class ConsoleLoggingTransformer(
    transformed: ByteChannel,
    prefix: String,
) : LoggingTransformer(transformed = transformed, prefix = prefix, logFunction = ConsoleLogFunction)

object ConsoleLogFunction : (String) -> Unit {
    override fun invoke(data: String) {
        println(data)
    }
}
