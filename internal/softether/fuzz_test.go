package softether

import "testing"

func FuzzDecodePack(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	p := NewPack()
	p.Add("test", TypeStr, StrValue("value"))
	data, _ := p.Encode()
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		p2, err := Decode(data)
		if err != nil {
			return
		}
		out, err := p2.Encode()
		if err != nil {
			return
		}
		_, _ = Decode(out)
	})
}
