package objstore

import (
	"fmt"
	"net/url"
)

// Key layout (platform/02 §5). tenant/project are UUID strings.
func RecordingPrefix(tenant, project, recordingID string) string {
	return fmt.Sprintf("%s/%s/recordings/%s/", tenant, project, url.PathEscape(recordingID))
}

func BlobKey(tenant, project, sha256hex string) string {
	return fmt.Sprintf("%s/%s/blobs/sha256/%s/%s/%s", tenant, project, sha256hex[:2], sha256hex[2:4], sha256hex)
}

func ExportKey(tenant, project, exportID, filename string) string {
	return fmt.Sprintf("%s/%s/exports/%s/%s", tenant, project, url.PathEscape(exportID), url.PathEscape(filename))
}
