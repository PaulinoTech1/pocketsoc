package org.atlasrf.collector

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Optional user-selected SAF delivery. No listeners, network, settings or radio changes. */
object DirectoryDelivery {
    fun deliver(context: Context, source: File, tree: Uri) {
        // Automatic Debian ingestion requires authenticated envelopes, even when empty.
        check(source.length() <= 16 * 1024 * 1024)
        check(JSONObject(source.readText(Charsets.UTF_8)).getString("kind") == "atlas-authenticated-export")
        val resolver = context.contentResolver
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val name = "atlas-${UUID.randomUUID()}"
        val partial = checkNotNull(DocumentsContract.createDocument(resolver, parent,
            "application/octet-stream", "$name.partial"))
        // A partial name is ignored by the inbox. Providers without rename support fail
        // explicitly; manual export remains available and the private spool is retained.
        resolver.openOutputStream(partial, "w")?.use { output ->
            source.inputStream().use { input -> input.copyTo(output, 16 * 1024) }
            output.flush()
        } ?: error("Document output unavailable")
        checkNotNull(DocumentsContract.renameDocument(resolver, partial, "$name.atlas.json"))
    }
}
