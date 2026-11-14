// SPDX-License-Identifier: LGPL-2.1-or-later

package profile

import (
	"fmt"
	"strings"
)

// Render writes the Spec as .ovpn text that parses to the profile Build
// returns. The result holds the private key and wrap key in full, so it
// belongs wherever the source profile would.
func (s Spec) Render() (string, error) {
	blocks, ds, err := s.directives()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, d := range ds {
		b.WriteString(d.String())
		b.WriteByte('\n')
	}
	for _, blk := range blocks {
		closing := "</" + blk.tag + ">"
		body := string(blk.body)
		for line := range strings.SplitSeq(body, "\n") {
			if strings.TrimSpace(line) == closing {
				return "", fmt.Errorf("profile: spec: the %s body contains its own closing tag", blk.tag)
			}
		}
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		fmt.Fprintf(&b, "<%s>\n%s%s\n", blk.tag, body, closing)
	}
	return b.String(), nil
}
