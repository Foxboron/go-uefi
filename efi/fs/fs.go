package fs

import "github.com/spf13/afero"

// Storage backend
var (
	Fs = afero.NewOsFs()
)

func SetFS(f afero.Fs) {
	Fs = f
}
