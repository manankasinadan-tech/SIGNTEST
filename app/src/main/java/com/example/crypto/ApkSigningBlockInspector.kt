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
    private const val ZIP_CD_SIG = 0x02014b50
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
        val pairs: List<SigningBlockPairInfo>,
        val isZipAligned4: Boolean
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
                    return RawSigningBlockParse(false, -1L, 0L, emptyList(), false)
                }
                val cdInfo = findCentralDirectoryInfo(raf, fileLen)
                    ?: return RawSigningBlockParse(false, -1L, 0L, emptyList(), false)

                val cdOffset = cdInfo.first
                val cdSize = cdInfo.second
                val aligned4 = checkZipAlignment4(raf, cdOffset, cdSize)

                if (cdOffset < 32) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList(), aligned4)
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
                    return RawSigningBlockParse(false, -1L, 0L, emptyList(), aligned4)
                }

                val totalSize = sizeOfBlockFooter + 8L
                val blockStart = cdOffset - totalSize
                if (blockStart < 0 || totalSize > 32L * 1024L * 1024L) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList(), aligned4)
                }

                raf.seek(blockStart)
                val headerSizeBuf = ByteArray(8)
                raf.readFully(headerSizeBuf)
                val sizeOfBlockHeader = ByteBuffer.wrap(headerSizeBuf)
                    .order(ByteOrder.LITTLE_ENDIAN).long
                if (sizeOfBlockHeader != sizeOfBlockFooter) {
                    return RawSigningBlockParse(false, -1L, 0L, emptyList(), aligned4)
                }

                val pairsLen = (sizeOfBlockFooter - 24L).toInt()
                if (pairsLen <= 0) {
                    return RawSigningBlockParse(true, blockStart, totalSize, emptyList(), aligned4)
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
                    pairs = pairs,
                    isZipAligned4 = aligned4
                )
            }
        } catch (_: Exception) {
            RawSigningBlockParse(false, -1L, 0L, emptyList(), false)
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

    private fun findCentralDirectoryInfo(raf: RandomAccessFile, fileLen: Long): Pair<Long, Long>? {
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
                val bb = ByteBuffer.wrap(buf, i, ZIP_EOCD_MIN_SIZE).slice().order(ByteOrder.LITTLE_ENDIAN)
                val sig = bb.int
                if (sig != ZIP_EOCD_SIG) continue
                val commentLen = bb.getShort(20).toInt() and 0xFFFF
                if (i + ZIP_EOCD_MIN_SIZE + commentLen == searchLen) {
                    val cdSize = bb.getInt(12).toLong() and 0xFFFFFFFFL
                    val cdOffset = bb.getInt(16).toLong() and 0xFFFFFFFFL
                    return cdOffset to cdSize
                }
            }
        }
        return null
    }

    private fun checkZipAlignment4(raf: RandomAccessFile, cdOffset: Long, cdSize: Long): Boolean {
        return try {
            if (cdSize <= 0 || cdSize > 16L * 1024L * 1024L) return false
            raf.seek(cdOffset)
            val cdBytes = ByteArray(cdSize.toInt())
            raf.readFully(cdBytes)
            val buf = ByteBuffer.wrap(cdBytes).order(ByteOrder.LITTLE_ENDIAN)
            while (buf.remaining() >= 46) {
                val sig = buf.int
                if (sig != ZIP_CD_SIG) break
                val compressionMethod = buf.getShort(buf.position() + 6).toInt() and 0xFFFF
                val nameLen = buf.getShort(buf.position() + 24).toInt() and 0xFFFF
                val extraLen = buf.getShort(buf.position() + 26).toInt() and 0xFFFF
                val commentLen = buf.getShort(buf.position() + 28).toInt() and 0xFFFF
                val localHeaderOffset = buf.getInt(buf.position() + 38).toLong() and 0xFFFFFFFFL

                if (compressionMethod == 0) {
                    // Check data offset alignment of first stored entry using local header
                    val savedPos = buf.position()
                    if (localHeaderOffset + 30 < cdOffset) {
                        val lh = ByteArray(30)
                        raf.seek(localHeaderOffset)
                        raf.readFully(lh)
                        val lhBuf = ByteBuffer.wrap(lh).order(ByteOrder.LITTLE_ENDIAN)
                        val lhNameLen = lhBuf.getShort(26).toInt() and 0xFFFF
                        val lhExtraLen = lhBuf.getShort(28).toInt() and 0xFFFF
                        val dataOffset = localHeaderOffset + 30 + lhNameLen + lhExtraLen
                        if (dataOffset % 4L != 0L) {
                            return false
                        }
                    }
                    buf.position(savedPos)
                }
                val skip = 42 + nameLen + extraLen + commentLen
                if (skip > buf.remaining()) break
                buf.position(buf.position() + skip)
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
