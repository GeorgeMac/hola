package yaml

import (
	"io"
	"io/ioutil"

	"github.com/georgemac/hola/lib/identity"
	yaml "gopkg.in/yaml.v2"
)

type Storage struct {
	Identities map[string]identity.Identity
	identities []identity.Identity
}

func NewStorage() *Storage {
	return &Storage{Identities: map[string]identity.Identity{}}
}

func (s *Storage) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if err := unmarshal(&s.identities); err != nil {
		return err
	}

	for _, id := range s.identities {
		s.Identities[id.Key] = id
	}

	return nil
}

func (s *Storage) Fetch(key string) (id identity.Identity, ok bool, err error) {
	id, ok = s.Identities[key]
	return
}

func (s *Storage) ReadFrom(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, s)
}
