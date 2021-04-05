// +build windows

package posture

import (
	"testing"
)

func TestRunningProcess(t *testing.T) {
	p := Process("C:\\Windows\\System32\\svchost.exe")
	if !p.IsRunning {
		t.Fail()
	}
}

func TestRunningProcessCaseInsensitive(t *testing.T) {
	p := Process("C:\\windows\\system32\\SVCHOST.EXE")
	if !p.IsRunning {
		t.Fail()
	}
}

func TestSlashNormalizationForwardSlash(t *testing.T) {
	p := Process("C:/windows/system32/SVCHOST.EXE")
	if !p.IsRunning {
		t.Fail()
	}
}

func TestSlashNormalizationExtraSlashes(t *testing.T) {
	p := Process("C:/windows///system32////SVCHOST.EXE")
	if !p.IsRunning {
		t.Fail()
	}
}