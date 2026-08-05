/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package acquire

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
)

// extractZitiBinary scans the tar.gz stream in r for the ziti binary (an entry whose
// base name is "ziti", at any depth) and writes it to dstPath with the executable
// bit set.
func extractZitiBinary(r io.Reader, dstPath string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("opening gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("archive does not contain a ziti binary")
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != "ziti" {
			continue
		}

		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", dstPath, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return fmt.Errorf("extracting ziti binary: %w", err)
		}
		if err := out.Close(); err != nil {
			return err
		}
		// the mode on OpenFile only applies if it created the file; the caller may
		// hand us a pre-created temp file, so set the executable bit explicitly
		return os.Chmod(dstPath, 0o755)
	}
}
