package scriptguard

import "bytes"

// sizeCap is where size bounds saturate, far above any element the engine's
// 100,000,000-byte stack memory limit admits and far below int64 overflow.
const sizeCap int64 = 1 << 40

// knownMax is the longest element whose exact bytes the analysis keeps: the
// longest stack index, count or size an honest script pushes is a few bytes,
// and 8 covers any int64.
const knownMax = 8

// elem bounds one stack element: its length is at most n, and when known is
// set its bytes are exactly v.
type elem struct {
	n     int64
	v     []byte
	known bool
}

func sized(n int64) elem { return elem{n: min(n, sizeCap)} }

// exact is the element whose bytes are b, keeping them when short.
func exact(b []byte) elem {
	if len(b) > knownMax {
		return elem{n: int64(len(b))}
	}
	return elem{n: int64(len(b)), v: b, known: true}
}

func plus(a, b int64) int64 { return min(a+b, sizeCap) }

// join bounds both a and b.
func (a elem) join(b elem) elem {
	r := elem{n: max(a.n, b.n)}
	if a.known && b.known && bytes.Equal(a.v, b.v) {
		r.v, r.known = a.v, true
	}
	return r
}

// astack bounds a stack: el holds its top len(el) elements, el[len(el)-1]
// the top one, and below them there are at most rest more elements, each
// at most restN long. rest is only an upper bound: a pop the real stack
// cannot serve fails there, so assuming the element exists over-approximates.
type astack struct {
	el    []elem
	rest  int
	restN int64
}

// depth is an upper bound on the number of elements.
func (s *astack) depth() int { return len(s.el) + s.rest }

func (s *astack) push(e elem) { s.el = append(s.el, e) }

// pop removes the top element; ok is false when the stack is surely empty,
// where the engine fails.
func (s *astack) pop() (elem, bool) {
	if n := len(s.el); n > 0 {
		e := s.el[n-1]
		s.el = s.el[:n-1]
		return e, true
	}
	if s.rest > 0 {
		s.rest--
		return sized(s.restN), true
	}
	return elem{}, false
}

// peek returns the element i below the top; ok is false when the stack
// surely has no such element.
func (s *astack) peek(i int) (elem, bool) {
	if i < len(s.el) {
		return s.el[len(s.el)-1-i], true
	}
	if i-len(s.el) < s.rest {
		return sized(s.restN), true
	}
	return elem{}, false
}

// roll moves the element i below the top to the top, as OP_ROLL does.
func (s *astack) roll(i int) bool {
	if i < len(s.el) {
		k := len(s.el) - 1 - i
		e := s.el[k]
		copy(s.el[k:], s.el[k+1:])
		s.el[len(s.el)-1] = e
		return true
	}
	if i-len(s.el) < s.rest {
		s.rest--
		s.push(sized(s.restN))
		return true
	}
	return false
}

// collapse forgets where each element is, keeping only how many there may
// be and how long any may be, for an opcode whose effect on positions the
// analysis cannot tell.
func (s *astack) collapse() {
	s.restN = s.maxN()
	s.rest += len(s.el)
	s.el = nil
}

// maxN bounds every element.
func (s *astack) maxN() int64 {
	m := int64(0)
	if s.rest > 0 {
		m = s.restN
	}
	for _, e := range s.el {
		m = max(m, e.n)
	}
	return m
}

func (s *astack) clone() astack {
	return astack{el: append([]elem(nil), s.el...), rest: s.rest, restN: s.restN}
}

// below bounds the region under the top w elements: how many elements it
// may hold and how long any may be.
func (s *astack) below(w int) (count int, n int64) {
	extra := len(s.el) - w
	if s.rest > 0 {
		n = s.restN
	}
	for _, e := range s.el[:extra] {
		n = max(n, e.n)
	}
	return extra + s.rest, n
}

// join makes s bound both s and o, in place: their top elements pair up,
// and whatever one has below the other's window becomes part of the region
// below. o is left as it was.
func (s *astack) join(o *astack) {
	w := min(len(s.el), len(o.el))
	sc, sn := s.below(w)
	oc, on := o.below(w)
	for i := 1; i <= w; i++ {
		s.el[len(s.el)-i] = s.el[len(s.el)-i].join(o.el[len(o.el)-i])
	}
	s.el = s.el[len(s.el)-w:]
	s.rest, s.restN = max(sc, oc), 0
	if sc > 0 {
		s.restN = sn
	}
	if oc > 0 {
		s.restN = max(s.restN, on)
	}
}

// dupJoin makes s bound both s and s with its top element x pushed again,
// for an OP_IFDUP whose condition the analysis cannot tell: the join of
// the two, done in place.
func (s *astack) dupJoin(x elem) {
	if len(s.el) == 0 {
		s.restN = max(s.restN, x.n)
		if s.rest == 0 {
			s.restN = x.n
		}
		s.rest++
		return
	}
	bottom := s.el[0]
	for j := 0; j+1 < len(s.el); j++ {
		s.el[j] = s.el[j].join(s.el[j+1])
	}
	if s.rest == 0 {
		s.restN = bottom.n
	}
	s.restN = max(s.restN, bottom.n)
	s.rest++
}
