package gbipcheck

import "testing"

func Test1(t *testing.T) {
	if !IsGB("5.150.161.0") {
		t.Error("Should be in UK")
	}
}

func Test2(t *testing.T) {
	if IsGB("5.150.128.1") {
		t.Error("Should NOT be in UK")
	}
}

func Test3(t *testing.T) {
	if IsGB("1.1.1.1") {
		t.Error("Should be in UK")
	}
}
func Test4(t *testing.T) {
	if IsGB("255.255.255.255") {
		t.Error("Should NOT be in UK")
	}
}
