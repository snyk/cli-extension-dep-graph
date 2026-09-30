package nuget

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Byte order marks. .NET tooling has emitted all three over the years: modern
// `nuget restore` writes UTF-8 with a BOM, while .nuspec files inside older
// .nupkg archives are frequently UTF-16.
var (
	bomUTF8    = []byte{0xEF, 0xBB, 0xBF}
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

// decodeXML unmarshals XML that may be UTF-16 encoded.
//
// encoding/xml rejects any declared encoding other than UTF-8, so the bytes are
// transcoded up front and the charset reader then hands them straight back.
// That is the same net effect as snyk-nuget-plugin decoding to a string before
// parsing, without its sniffing for the U+FFFD that a mis-decode leaves behind
// (nuspec-parser.ts, detectNuspecContentEncoding).
//
// The charset reader accepts every label rather than checking it against the
// bytes, which matches upstream: a file whose declaration disagrees with its
// contents is read as whatever its BOM says, or as UTF-8.
//
// Element and attribute names are matched without regard to case: MSBuild and
// the .NET tooling around it treat them that way, and a lowercase `<version>`
// that restores fine must not drop a package here. Struct tags for anything
// decoded through this function therefore have to be written in lowercase.
func decodeXML(data []byte, into any) error {
	decoder := xml.NewDecoder(bytes.NewReader(toUTF8(data)))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	if err := xml.NewTokenDecoder(lowercaseNames{decoder}).Decode(into); err != nil {
		return fmt.Errorf("decoding XML: %w", err)
	}

	return nil
}

// lowercaseNames folds element and attribute local names to lowercase as tokens
// are read, which is how a case-sensitive struct-tag decoder gets to match
// case-insensitively. Namespaces and character data are left alone.
type lowercaseNames struct {
	decoder *xml.Decoder
}

var _ xml.TokenReader = lowercaseNames{}

func (l lowercaseNames) Token() (xml.Token, error) {
	token, err := l.decoder.Token()
	if err != nil {
		// io.EOF must reach the caller unwrapped for the decoder to see the
		// end of the document.
		return nil, err //nolint:wrapcheck // sentinel passthrough
	}

	switch t := token.(type) {
	case xml.StartElement:
		t.Name.Local = strings.ToLower(t.Name.Local)

		attrs := make([]xml.Attr, len(t.Attr))
		for i, attr := range t.Attr {
			attr.Name.Local = strings.ToLower(attr.Name.Local)
			attrs[i] = attr
		}

		t.Attr = attrs

		return t, nil
	case xml.EndElement:
		t.Name.Local = strings.ToLower(t.Name.Local)

		return t, nil
	default:
		return token, nil
	}
}

// toUTF8 strips a UTF-8 BOM, or transcodes UTF-16 to UTF-8 when a UTF-16 BOM is
// present. Anything else is returned unchanged and read as UTF-8, which is what
// snyk-nuget-plugin does with a file it cannot identify.
func toUTF8(data []byte) []byte {
	switch {
	case bytes.HasPrefix(data, bomUTF8):
		return data[len(bomUTF8):]
	case bytes.HasPrefix(data, bomUTF16LE):
		return utf16ToUTF8(data[len(bomUTF16LE):], binary.LittleEndian)
	case bytes.HasPrefix(data, bomUTF16BE):
		return utf16ToUTF8(data[len(bomUTF16BE):], binary.BigEndian)
	default:
		return data
	}
}

// utf16ToUTF8 decodes BOM-less UTF-16 code units. A trailing odd byte is
// dropped: it cannot be part of a code unit, and refusing the whole file over
// it would lose a manifest that every other tool reads happily.
func utf16ToUTF8(data []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:i+2]))
	}

	runes := utf16.Decode(units)

	out := make([]byte, 0, len(runes)*utf8.UTFMax)
	for _, r := range runes {
		out = utf8.AppendRune(out, r)
	}

	return out
}

// xmlRootElement returns the local name of the document's root element, or ""
// when there is none. Decoding into a struct with no XMLName accepts whatever
// root it is given, so this is how a manifest whose root element is wrong gets
// reported as wrong rather than as empty.
func xmlRootElement(data []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(toUTF8(data)))
	decoder.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}

		if start, ok := token.(xml.StartElement); ok {
			return start.Name.Local
		}
	}
}
