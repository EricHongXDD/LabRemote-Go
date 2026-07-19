package events

type Sink interface {
	Emit(name string, payload any)
}

type Func func(name string, payload any)

func (f Func) Emit(name string, payload any) {
	if f != nil {
		f(name, payload)
	}
}

type Nop struct{}

func (Nop) Emit(string, any) {}
