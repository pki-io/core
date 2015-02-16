package index

func AppendUnique(slice []string, val string) []string {
	found := false
	for _, v := range slice {
		if v == val {
			found = true
			break
		}
	}

	if found {
		return slice
	} else {
		return append(slice, val)
	}
}
