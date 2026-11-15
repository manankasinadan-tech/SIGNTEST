package com.example.crypto

import com.example.model.SigningBlockPairInfo
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.jar.JarFile

object ApkSigningBlockInspector {

    private const val ZIP_EOCD_MIN_SIZE = 22
    private const val ZIP_EOCD_SIG = 0x06054b50
    private const val ZIP_MAX_COMMENT_SIZE = 65535
    private const val APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L // "APK Sig "
    private const val APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L // "Block 42"

    private val KNOWN_BLOCK_NAMES = mapOf(
        0x7109871a to "APK Signature Scheme v2",
        0xf05368c0.toInt() to "APK Signature Scheme v3",
        0x1b93ad61 to "APK Signature Scheme v3.1",
        0x6dff800d to "SourceStamp v2",
        0x2b09189e to "SourceStamp v1",
        0x42726577 to "Verity Padding Block",
        0x504b4453 to "Play Dependency Info (Frosting)",
        0x71777777 to "APK Channel / Metadata Block"
    )

    data class RawSigningBlockParse(
        val present: Boolean,
        val blockOffset: Long,
        val blockSizeBytes: Long,
        val pairs: List<SigningBlockPairInfo>
    )

    data class RawV1Inspection(
        val signerFiles: List<String>,
        val sfFiles: List<String>,
        val manifestDigestAlgs: List<String>,
        val totalEntryCount: Int,
        val manifestEntryCount: Int
    )

    fun inspectSigningBlock(apkFile: File): RawSigningBlockParse {
        return try {
            RandomAccessFile(apkFile, "r").use { raf ->
                val fileLen = raf.length()
                if (fileLen < ZIP_EOCD_MIN_SIZE) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList())
                }
                val cdOffset = findCentralDirectoryOffset(raf, fileLen)
                    ?: return RawSigningBlockParse(false, -1L, 0L, emptyList())

                if (cdOffset < 32) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList())
                }

                // Read 24 bytes immediately preceding Central Directory (8-byte size + 16-byte magic)
                raf.seek(cdOffset - 24)
                val footer = ByteArray(24)
                raf.readFully(footer)
                val footerBuf = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN)
                val sizeOfBlockFooter = footerBuf.long
                val magicLo = footerBuf.long
                val magicHi = footerBuf.long

                if (magicLo != APK_SIG_BLOCK_MAGIC_LO || magicHi != APK_SIG_BLOCK_MAGIC_HI) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList())
                }

                val totalSize = sizeOfBlockFooter + 8L
                val blockStart = cdOffset - totalSize
                if (blockStart < 0 || totalSize > 32L * 1024L * 1024L) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList())
                }

                raf.seek(blockStart)
                val headerSizeBuf = ByteArray(8)
                raf.readFully(headerSizeBuf)
                val sizeOfBlockHeader = ByteBuffer.wrap(headerSizeBuf)
                    .order(ByteOrder.LITTLE_ENDIAN).long
                if (sizeOfBlockHeader != sizeOfBlockFooter) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList())
                }

                val pairsLen = (sizeOfBlockFooter - 24L).toInt()
                if (pairsLen <= 0) {
                    return RawSigningBlockParse(true, blockStart, totalSize, emptyList())
                }

                val pairsBytes = ByteArray(pairsLen)
                raf.readFully(pairsBytes)
                val buf = ByteBuffer.wrap(pairsBytes).order(ByteOrder.LITTLE_ENDIAN)
                val pairs = mutableListOf<SigningBlockPairInfo>()
                while (buf.remaining() >= 12) {
                    val pairLen = buf.long
                    if (pairLen < 4 || pairLen > buf.remaining()) break
                    val id = buf.int
                    val valueSize = (pairLen - 4).toInt()
                    buf.position(buf.position() + valueSize)
                    val idHex = "0x%08x".format(id)
                    val name = KNOWN_BLOCK_NAMES[id] ?: "Custom / Unknown Block"
                    pairs += SigningBlockPairInfo(
                        idHex = idHex,
                        name = name,
                        sizeBytes = valueSize
                    )
                }

                RawSigningBlockParse(
                    present = true,
                    blockOffset = blockStart,
                    blockSizeBytes = totalSize,
                    pairs = pairs
                )
            }
        } catch (_: Exception) {
            RawSigningBlockParse(false, -1L, 0L, emptyList())
        }
    }

    fun inspectV1Jar(apkFile: File): RawV1Inspection {
        return try {
            JarFile(apkFile, false).use { jar ->
                val signerFiles = mutableListOf<String>()
                val sfFiles = mutableListOf<String>()
                var totalEntries = 0
                val digestAlgs = linkedSetOf<String>()

                val entries = jar.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    totalEntries++
                    val upper = entry.name.uppercase()
                    if (upper.startsWith("META-INF/")) {
                        when {
                            upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC") -> {
                                signerFiles += entry.name
                            }
                            upper.endsWith(".SF") -> {
                                sfFiles += entry.name
                            }
                        }
                    }
                }

                val manifest = jar.manifest
                val manifestEntries = manifest?.entries?.size ?: 0
                manifest?.entries?.values?.forEach { attrs ->
                    attrs.keys.forEach { key ->
                        val k = key.toString()
                        if (k.endsWith("-Digest", ignoreCase = true)) {
                            digestAlgs += k.removeSuffix("-Digest").removeSuffix("-digest")
                        }
                    }
                }

                RawV1Inspection(
                    signerFiles = signerFiles.sorted(),
                    sfFiles = sfFiles.sorted(),
                    manifestDigestAlgs = digestAlgs.toList(),
                    totalEntryCount = totalEntries,
                    manifestEntryCount = manifestEntries
                )
            }
        } catch (_: Exception) {
            RawV1Inspection(emptyList(), emptyList(), emptyList(), 0, 0)
        }
    }

    private fun findCentralDirectoryOffset(raf: RandomAccessFile, fileLen: Long): Long? {
        val searchLen = minOf(fileLen, (ZIP_EOCD_MIN_SIZE + ZIP_MAX_COMMENT_SIZE).toLong()).toInt()
        val startOffset = fileLen - searchLen
        raf.seek(startOffset)
        val buf = ByteArray(searchLen)
        raf.readFully(buf)

        for (i in searchLen - ZIP_EOCD_MIN_SIZE downTo 0) {
            if (buf[i].toInt() == 0x50 &&
                buf[i + 1].toInt() == 0x4b &&
                buf[i + 2].toInt() == 0x05 &&
                buf[i + 3].toInt() == 0x06
            ) {
                val bb = ByteBuffer.wrap(buf, i, ZIP_EOCD_MIN_SIZE).order(ByteOrder.LITTLE_ENDIAN)
                val sig = bb.int
                if (sig != ZIP_EOCD_SIG) continue
                val commentLen = bb.getShort(20).toInt() and 0xFFFF
                if (i + ZIP_EOCD_MIN_SIZE + commentLen == searchLen) {
                    return bb.getInt(16).toLong() and 0xFFFFFFFFL
                }
            }
        }
        return null
    }
}
