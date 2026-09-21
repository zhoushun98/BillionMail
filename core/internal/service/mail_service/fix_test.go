package mail_service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPlaceholderHostname(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", true},
		{"only whitespace", "   ", true},
		{"install template default", "mail.example.com", true},
		{"localhost", "localhost", true},
		{"localhost.localdomain", "localhost.localdomain", true},
		{"placeholder with surrounding spaces", "  mail.example.com  ", true},

		// 真实主机名不能被当成占位值
		{"real mail hostname", "mail.sanaoman.asia", false},
		{"real mail hostname with subdomain", "mail.mx1.example.org", false},

		// 裸域不是占位值：它是 FixPostfixMainConfig 写坏的真实值，
		// 需要由 resolvePostfixHostname 经 FormatMX 修正，而不是在这里被判为占位。
		{"bare domain", "sanaoman.asia", false},
		{"bare domain example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPlaceholderHostname(tt.input))
		})
	}
}
