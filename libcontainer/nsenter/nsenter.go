// +build linux,!gccgo

package nsenter

/*
#cgo CFLAGS: -Wall -g
extern void nsexec();
void __attribute__((constructor)) init(void) {
	nsexec();
}
*/
import "C"
