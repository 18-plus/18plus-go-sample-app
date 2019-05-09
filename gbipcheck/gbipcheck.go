package gbipcheck

import (
	"strconv"
	"strings"
)

func IsGB(ip1 string) (result bool) {
	ip2 := IPToUint32(ip1)

	len1 := len(ipranges) / 2
	// len2 := len1 / 2

	a := 0
	b := len1

	for {

		c := (a + b) / 2

		// fmt.Printf("%d %d %d \n", a, b, c)

		if ip2 >= ipranges[c*2+0] && ip2 <= ipranges[c*2+1] {
			return true
		}

		if a == c {
			return false
		}

		if ip2 < ipranges[c*2+0] {
			b = c
			continue
		}

		if ip2 > ipranges[c*2+1] {
			a = c
			continue
		}

		return false

	} // END for

} // END func IsGB

func IPToUint32(ip string) (result uint32) {

	ss := strings.Split(ip, ".")

	i0, _ := strconv.ParseUint(ss[0], 10, 8)
	i1, _ := strconv.ParseUint(ss[1], 10, 8)
	i2, _ := strconv.ParseUint(ss[2], 10, 8)
	i3, _ := strconv.ParseUint(ss[3], 10, 8)

	result = uint32((i0 << 24) | (i1 << 16) | (i2 << 8) | i3)

	return

} // END func IPToUInt32
