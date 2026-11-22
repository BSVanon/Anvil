package messaging

// privateHomeResolver gives a current private claim precedence over adverts.
type privateHomeResolver struct {
	store    *PrivateHomeStore
	own      string
	fallback HomeResolver
}

// NewPrivateHomeResolver composes private claims in front of an advert resolver.
func NewPrivateHomeResolver(store *PrivateHomeStore, ownIdentity string, fallback HomeResolver) HomeResolver {
	if fallback == nil {
		fallback = AlwaysUnadvertised
	}
	return &privateHomeResolver{store: store, own: ownIdentity, fallback: fallback}
}

func (r *privateHomeResolver) Resolve(member string) (Resolution, error) {
	record, ok, err := r.store.Current(member)
	if err != nil {
		return Resolution{}, err
	}
	if !ok {
		return r.fallback.Resolve(member)
	}
	isHome := false
	hasOther := false
	for _, home := range record.Homes {
		if home == r.own {
			isHome = true
		} else {
			hasOther = true
		}
	}
	if isHome {
		return Resolution{State: Home, HasOtherHost: hasOther}, nil
	}
	return Resolution{State: Elsewhere}, nil
}
