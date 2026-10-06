/*
 * A host that offers a guest every paravirtual feature KVM has.
 *
 * Preloaded into a VMM (LD_PRELOAD), it sets every bit of the registers of
 * KVM's feature leaf in what the VMM hands KVM for each vCPU
 * (KVM_SET_CPUID2), whatever the VMM chose to offer: the clock, steal time,
 * PV EOI, asynchronous page faults, the TLB flush and the rest, and every
 * hint. The guest then sees all of them offered, as a host that meant it
 * harm could have it see them. test/session/hardware.sh boots a guest under
 * it and reads from the host's trace of that VMM what the guest took.
 *
 *   cc -shared -fPIC -O2 -o kvm-offer-all.so kvm-offer-all.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>

#define KVM_FEATURE_LEAF 0x40000001u

int ioctl(int fd, unsigned long request, ...)
{
	static int (*real)(int, unsigned long, ...);
	va_list ap;
	void *arg;

	if (!real)
		real = dlsym(RTLD_NEXT, "ioctl");
	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (request == KVM_SET_CPUID2 && arg) {
		struct kvm_cpuid2 *cpuid = arg;

		for (unsigned int i = 0; i < cpuid->nent; i++) {
			struct kvm_cpuid_entry2 *entry = &cpuid->entries[i];

			if (entry->function == KVM_FEATURE_LEAF) {
				entry->eax = 0xffffffffu;
				entry->edx = 0xffffffffu;
			}
		}
	}
	return real(fd, request, arg);
}
