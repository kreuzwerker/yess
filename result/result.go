package result

import (
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

const errFailedToDecode = "failed to decode result"

// Result represents the result of a split into n parts with the given threshold.
type Result struct {
	Parts     []*Part `json:"parts"`
	Threshold int     `json:"threshold"`
}

// Load loads a result from a reader, e.g. a file
func Load(r io.Reader) (*Result, error) {

	var result Result

	r2 := json.NewDecoder(r)

	if err := r2.Decode(&result); err != nil {
		return nil, errors.Wrapf(err, errFailedToDecode)
	}

	return &result, nil

}

// Save stores a result in a writer, e.g. a file
func (r *Result) Save(w io.Writer) error {

	w2 := json.NewEncoder(w)

	w2.SetIndent("", "\t")
	w2.Encode(r)

	return nil

}
