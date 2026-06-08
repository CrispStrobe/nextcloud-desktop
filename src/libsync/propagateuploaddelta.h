/*
 * SPDX-FileCopyrightText: 2026 CrispCloud Contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Block-level delta sync upload: instead of re-uploading entire files,
 * compute Adler-32 + SHA-256 block maps and upload only changed blocks
 * via the crispcloud_delta server app's REST API.
 *
 * Requires the crispcloud_delta Nextcloud/ownCloud app to be installed.
 * Falls back to normal upload if the app is not detected.
 */

#pragma once

#include "propagateupload.h"

#include <QCryptographicHash>

namespace OCC {

Q_DECLARE_LOGGING_CATEGORY(lcPropagateUploadDelta)

/**
 * @brief Block signature: Adler-32 weak hash + SHA-256 strong hash for one block.
 */
struct BlockSignature {
    int blockIndex = 0;
    qint64 offset = 0;
    qint64 size = 0;
    quint32 weakHash = 0;
    QByteArray strongHash; // hex-encoded SHA-256
};

/**
 * @brief Block map for a file: one BlockSignature per block.
 */
struct BlockMap {
    QString filePath;
    qint64 totalSize = 0;
    qint64 blockSize = 0;
    int blockCount = 0;
    QVector<BlockSignature> signatures;
    QString etag;
};

/**
 * @brief PropagateUploadFileDelta implements block-level delta sync upload.
 *
 * Flow:
 *   1. Probe server for crispcloud_delta app via GET /api/status
 *   2. Fetch remote block map via GET /api/blockmap/{path}
 *   3. Compute local block map (Adler-32 + SHA-256 per 4 MB block)
 *   4. Compare: find changed block indices
 *   5. Upload only changed blocks via POST /api/blocks/{path}?offset=N&size=M
 *   6. Finalize via POST /api/finalize/{path}
 *   7. Fall back to normal chunked upload if any step fails
 *
 * @ingroup libsync
 */
class PropagateUploadFileDelta : public PropagateUploadFileCommon
{
    Q_OBJECT

public:
    PropagateUploadFileDelta(OwncloudPropagator *propagator, const SyncFileItemPtr &item);

    void doStartUpload() override;

public slots:
    void abort(PropagatorJob::AbortType abortType) override;

private slots:
    void slotStatusCheckFinished();
    void slotBlockMapFetched();
    void slotBlockUploaded();
    void slotFinalizeFinished();

private:
    /// Adler-32 checksum (RFC 1950), matching the server's PHP implementation.
    static quint32 adler32(const QByteArray &data);

    /// Compute the local block map for the file being uploaded.
    BlockMap computeLocalBlockMap(const QString &filePath, qint64 blockSize);

    /// Parse server JSON block map response.
    static BlockMap parseServerBlockMap(const QByteArray &json);

    /// Compare local vs remote block maps, return list of changed block indices.
    static QVector<int> findChangedBlocks(const BlockMap &local, const BlockMap &remote);

    /// Fall back to normal (non-delta) upload.
    void fallbackToNormalUpload();

    /// Upload the next changed block in the queue.
    void uploadNextBlock();

    static constexpr qint64 DefaultBlockSize = 4 * 1024 * 1024; // 4 MB
    static constexpr qint64 MinDeltaSyncSize = 10 * 1024 * 1024; // 10 MB

    QString _deltaAppBase;          // e.g. /index.php/apps/crispcloud_delta
    BlockMap _localBlockMap;
    BlockMap _remoteBlockMap;
    QVector<int> _changedBlocks;
    int _currentBlockIndex = 0;     // index into _changedBlocks
    bool _deltaAvailable = false;
};

} // namespace OCC
