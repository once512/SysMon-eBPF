// SPDX-License-Identifier: MIT
#include "metadata.h"
#include <cstring>
#include <linux/fanotify.h>
#include <stdexcept>
PermissionMetadata decode_permission_metadata(const void *data, std::size_t size, bool pidfd_mode)
{
    if (!data || size < sizeof(fanotify_event_metadata)) throw std::runtime_error("Short fanotify metadata record");
    fanotify_event_metadata metadata{};
    std::memcpy(&metadata, data, sizeof(metadata));
    PermissionMetadata result;
    result.file = OwnedFd(metadata.fd);
    fanotify_event_info_pidfd attachment{};
    // Own both delivered FDs before any ABI validation or identity inspection can throw.
    if (pidfd_mode && size == sizeof(metadata) + sizeof(attachment)) {
        std::memcpy(&attachment, static_cast<const char *>(data) + sizeof(metadata), sizeof(attachment));
        if (attachment.pidfd >= 0 && attachment.pidfd == metadata.fd)
            throw std::runtime_error("Fanotify event and requester FDs alias");
        result.requester.fd = OwnedFd(attachment.pidfd);
    }
    const auto expected = sizeof(metadata) + (pidfd_mode ? sizeof(attachment) : 0);
    if (metadata.vers != FANOTIFY_METADATA_VERSION || metadata.metadata_len != sizeof(metadata) ||
        metadata.event_len != size || size != expected)
        throw std::runtime_error("Unexpected fanotify metadata ABI");
    if (pidfd_mode) {
        if (attachment.hdr.info_type != FAN_EVENT_INFO_TYPE_PIDFD || attachment.hdr.len != sizeof(attachment) || attachment.hdr.pad)
            throw std::runtime_error("Unexpected fanotify pidfd attachment");
        // Release to the new owner; sentinels are negative and OwnedFd never closes them.
        result.requester = process_reference(result.requester.fd.release());
    }
    result.mask = metadata.mask;
    result.pid = metadata.pid;
    return result;
}
