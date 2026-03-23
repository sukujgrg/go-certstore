package certstore

import "unsafe"

func byteSlicePtr(data []byte) unsafe.Pointer {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Pointer(unsafe.SliceData(data))
}

func byteSliceStringView(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(data), len(data))
}
