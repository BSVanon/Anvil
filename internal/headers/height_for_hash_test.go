package headers

import "testing"

func TestHeightForHashRejectsTruncatedIndexValue(t *testing.T) {
	s := tmpStore(t)
	hash, err := s.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	key := append(append([]byte{}, prefixHash...), hash[:]...)
	if err := s.db.Put(key, []byte{0, 0, 0}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeightForHash(hash); err == nil {
		t.Fatal("expected an error for a truncated hash-height index value")
	}
}
