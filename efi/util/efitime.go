package util

import (
	"fmt"
	"time"
)

// Section 8.2 - Time Services

var (
	EFI_TIME_ADJUST_DAYLIGHT uint8  = 0x01
	EFI_TIME_IN_DAYLIGHT     uint8  = 0x02
	EFI_UNSPECIFIED_TIMEZONE uint16 = 0x07FF
)

type EFITime struct {
	Year       uint16 // 1900 - 9999 AKA Y99K y'all
	Month      uint8  // 1-12
	Day        uint8  // 1 -31
	Hour       uint8  // 0 - 23
	Minute     uint8  // 0 - 59
	Second     uint8  // 0 - 59
	Pad1       uint8
	Nanosecond uint32 // 0 - 999,999,999
	TimeZone   int16  // -1440 to 1440 or 2047
	Daylight   uint8
	Pad2       uint8
}

func (e *EFITime) Format() string {
	return fmt.Sprintf("%d-%d-%d %d:%d:%d:%d", e.Year, e.Month, e.Day, e.Hour, e.Minute, e.Second, e.Nanosecond)
}

type EFITImeCapabilitie struct {
	Resolution uint32
	Accuracy   uint32
	SetsToZero bool
}

func NewEFITime() *EFITime {
	t := time.Now()
	return &EFITime{
		Year:   uint16(t.Year()),
		Month:  uint8(t.Month()),
		Day:    uint8(t.Day()),
		Hour:   uint8(t.Hour()),
		Minute: uint8(t.Minute()),
		Second: uint8(t.Second()),
	}
}
