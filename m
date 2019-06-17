Return-Path: <kasan-dev+bncBCH67JWTV4DBBHVAUDUAKGQE5EYQYGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1849C494CF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:43 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id g56sf10634120qte.4
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809502; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jz6BmvCPd/ipMvGUNRDHKUQ5obI9E0sC49w6j03KSIUjg/ITf33B+jlx3Q0g05+DeZ
         uMaCemMuwPvA+aZMPDeGmeBg7XU4FO5+H0J1bJOvHPPHQVUjaknO7YB5dg+2GYouULwH
         yVoIIUoiCSsINw5WI3u7NmdkkzRWuM/aifilsS04keYfldzJZxByoufJo6ByIJLRsqVH
         Raf+N4Tbxa2S5g0fZ31NFESGGIEGlCMvUhMMbXovfnjt4oxvRRoGuBdEvvuw8KsLbVUx
         3C2IiKvPowW0gQkLJvMZx9gMjznxllMIJ9UpmcmtVhyhbzCI841vRL1KyhgvQp5H6yjn
         R1ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=ZESdHmxWnNXdINJV22+ocygoJU7o36YxTzPlP3wqIHs=;
        b=K3JQK8y6Zjcu+JEFFtM9rNDyubAMDNi9i7oOsWKZAeDeDRhRsaDRQFDmOXJWx8yfP0
         VFjFRH8lOu5ETeT+sB7UpNds1zie2yyA8QhkGTYgwRj497676S7xNuKt5qxMBVR9W7VD
         QUk7xbVYKztiRdzix5D0yeZr3l6jfW4jJS/tLVuMvRrTObtdw7EJt/OJE1ug4+fXcaUz
         r4xm/T0v+JTs/lJL6XAhP7WWoo7KQDhTGx8bLNV4GoBWQ4AkNTXCFXYHo387WA3kOuW/
         I21swY5vWcAHgOgkgG9alrctM7C59cDhXjiaJcWUsKp7wFEyBYMtKZgs7ba+P1CDlyAe
         3q6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HwbLfFk9;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZESdHmxWnNXdINJV22+ocygoJU7o36YxTzPlP3wqIHs=;
        b=DgBHqF4P4tAJjksLDN6tpTvUwR1Lh/dUQK7bE0KoQF3urBwaaouY5DIV5P9ISr/XF6
         72yLNO4kRtySyCrAsOjtaE/wFT8cb9/cWjbQ2kguV6EMPgrQMyVYhk2Tme+P0DMDfYYj
         jWkZSoiQjI31f0vk6qw7k0cS11iRvZbjkzrJ0mbuogt23y+ClcQFMLU+2LSSmz88ALLq
         qvrVm0wIT2ne0weplGKaTlguNXi8yy58XUGSTxWmqrB3GPEHEMDn69iWXGFUE7L2c88e
         CzhYh+0e5l5KP/Vf1tur4zLQFd0kQ0acvqGw6AlVImh1+8h724e7p1npZUk+BQV3RGEo
         ALIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZESdHmxWnNXdINJV22+ocygoJU7o36YxTzPlP3wqIHs=;
        b=KRsf7YUtq06slLRKRsOPrwmSPToNu3ib/x/IYBD8w+S6hFdmBFEOJLLxcUHOnacoQn
         U/zTzZc2YlMs7xL5/Ido5YQCbAL46fcXvLeb7vRKgrsRpp1ol/l2AwDVld7HekecSdL5
         +z6vf4c22bHugqvo/GpSh59sgPJ8foI4/zi5llK5STzL/Aepp6mMLmK0xd+z5ACw2GAq
         EqqNLHPKJkUJB1SgACypz1Ektk5V+SdEt3mo5UYAEUk+5C/8LM12y0tlkcARBuxP6taD
         T0KwT96Is0m26YYcpywP+c+FJfpp+qEvrdK3MsHq69ZNHvZBkkQq7KWeQLDnSXBDSjop
         bSvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZESdHmxWnNXdINJV22+ocygoJU7o36YxTzPlP3wqIHs=;
        b=N+CtVtMwDN33q4TDNaTIwKmxJbCzP61xObDr8kq8CpIQopaH+ovO2Kv+12Qy5J5n/G
         YnlyfiFQuZ9bTLQae9DNDOSUvCvjnocFl6EjhO/Hnbjfo6uQEgGE4OW/KHcLkMrszsSf
         HzSuqL7IY5Oji6vubJ+LwvwhkYc7Iic1j4akLaReJh9Y3RMbhQ7+04cKHlOvdDQkX1RT
         sTopfzaiQCXridK4iOxeNt56fgFIqyn1GQEckGTjKKc1Wz7ppUNkgZ+9J6KdRamFnKXL
         qpHY9oi689FlWprlM4bj5XKYhxrh6A4w4QQbP5Dv9yEK6PIzxU1yjmOsAcgqNeOzcCMD
         G16Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXTrwhyTvmcEzWx5XlVHUNfnxP2qs8pYZWtbik4Y674N/WLrRvt
	IK0sAzJUjDhAJj6dN5yZ0sA=
X-Google-Smtp-Source: APXvYqzM+LreT0EEtqbmKyeublpVUxquMJFrXXsgHevhg+RBofNeORSjKodiZ9Lc446OUS+4K2WDxw==
X-Received: by 2002:a37:b7c6:: with SMTP id h189mr90990053qkf.347.1560809502153;
        Mon, 17 Jun 2019 15:11:42 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4e4c:: with SMTP id c73ls4011857qkb.3.gmail; Mon, 17 Jun
 2019 15:11:41 -0700 (PDT)
X-Received: by 2002:a05:620a:44:: with SMTP id t4mr1962651qkt.189.1560809501888;
        Mon, 17 Jun 2019 15:11:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809501; cv=none;
        d=google.com; s=arc-20160816;
        b=JDOoLO03XivEKiyvBDJbglDx9ZVG/jnplazJQr5B21dZV7mu8d21cWh/u+duad6F7b
         Cmov4Kbtuph1qVzZoiLahZ+nH1nmqgs+GmYc919dkf16RfpfLnfaQS/xUw97wHhoYmWD
         GaleXSZpuijIVUrcXWLjb613fIiCYKl3P0CmbBUgQA2xW/KFuusDs+uBKn3XUV9j1dy1
         7B8GN2yaG1mueqDcBYsdGLbQBdcF3BSN4DaqIN6mJD9G45/sbYbO6MP6iaBtQJ/a++R3
         +CTg8GJrrV7VyoSSRdcEqltdXY/IVTDc3h5tufHtAaTmGnWowR93UBRnf9XTk8pU4rAv
         W4Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=9hJzxrszcukVONnoGVdeWJlpdRxEpsd4fbXa7dt9GVI=;
        b=zpIhZABL+awMe/X3nywzw0eHrHkPigI6rFUY0ukDS307CiSQaQNov22NQzMMhr/7ci
         wkhRMv48EmBqFcVMa6P6aQKrZclaEUWvPLUsu/nEAlPFSOpW0BGD5EzB3nBP6TnC2JNH
         tkg/7rdLqv0yz4IR28BwAkdv27pPEnXlL36migUaWch4lZxMNf/5E3m0kYHg83az1xna
         RFQ3ulRQ2i4yP8zXTu0XXH0f4PB6HRpm+V7wQ3dkdSFErbA6PmQQGl/T8vuxNEM4Boc4
         9h2eazjpLUTKRJiwp6qYsZ1CFO+OcBnQYovFaL8fuGHjO/j9w78OPayQoGi8LsDTZl9w
         /mvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HwbLfFk9;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id u124si632848qkb.5.2019.06.17.15.11.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id r7so6406714pfl.3
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:41 -0700 (PDT)
X-Received: by 2002:a62:15c3:: with SMTP id 186mr53022791pfv.141.1560809500847;
        Mon, 17 Jun 2019 15:11:40 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.38
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:40 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Florian Fainelli <f.fainelli@gmail.com>,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	liuwenliang@huawei.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v6 0/6] KASan for arm
Date: Mon, 17 Jun 2019 15:11:28 -0700
Message-Id: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=HwbLfFk9;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi all,

Abbott submitted a v5 about a year ago here:

and the series was not picked up since then, so I rebased it against
v5.2-rc4 and re-tested it on a Brahma-B53 (ARMv8 running AArch32 mode)
and Brahma-B15, both LPAE and test-kasan is consistent with the ARM64
counter part.

We were in a fairly good shape last time with a few different people
having tested it, so I am hoping we can get that included for 5.4 if
everything goes well.

Changelog:

v6 - v5
- Resolve conflicts during rebase, and updated to make use of
  kasan_early_shadow_pte instead of kasan_zero_pte

v5 - v4
- Modify Andrey Ryabinin's email address.

v4 - v3
- Remove the fix of type conversion in kasan_cache_create because it has
  been fix in the latest version in:
  git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
- Change some Reviewed-by tag into Reported-by tag to avoid misleading.
  ---Reported by: Marc Zyngier <marc.zyngier@arm.com>
                  Russell King - ARM Linux <linux@armlinux.org.uk>
- Disable instrumentation for arch/arm/mm/physaddr.c

v3 - v2
- Remove this patch: 2 1-byte checks more safer for memory_is_poisoned_16
  because a unaligned load/store of 16 bytes is rare on arm, and this
  patch is very likely to affect the performance of modern CPUs.
  ---Acked by: Russell King - ARM Linux <linux@armlinux.org.uk>
- Fixed some link error which kasan_pmd_populate,kasan_pte_populate and
  kasan_pud_populate are in section .meminit.text but the function
  kasan_alloc_block which is called by kasan_pmd_populate,
  kasan_pte_populate and kasan_pud_populate is in section .init.text. So
  we need change kasan_pmd_populate,kasan_pte_populate and
  kasan_pud_populate into the section .init.text.
  ---Reported by: Florian Fainelli <f.fainelli@gmail.com>
- Fixed some compile error which caused by the wrong access instruction in
  arch/arm/kernel/entry-common.S.
  ---Reported by: kbuild test robot <lkp@intel.com>
- Disable instrumentation for arch/arm/kvm/hyp/*.
  ---Acked by: Marc Zyngier <marc.zyngier@arm.com>
- Update the set of supported architectures in
  Documentation/dev-tools/kasan.rst.
  ---Acked by:Dmitry Vyukov <dvyukov@google.com>
- The version 2 is tested by:
  Florian Fainelli <f.fainelli@gmail.com> (compile test)
  kbuild test robot <lkp@intel.com>       (compile test)
  Joel Stanley <joel@jms.id.au>           (on ASPEED ast2500(ARMv5))

v2 - v1
- Fixed some compiling error which happens on changing kernel compression
  mode to lzma/xz/lzo/lz4.
  ---Reported by: Florian Fainelli <f.fainelli@gmail.com>,
             Russell King - ARM Linux <linux@armlinux.org.uk>
- Fixed a compiling error cause by some older arm instruction set(armv4t)
  don't suppory movw/movt which is reported by kbuild.
- Changed the pte flag from _L_PTE_DEFAULT | L_PTE_DIRTY | L_PTE_XN to
  pgprot_val(PAGE_KERNEL).
  ---Reported by: Russell King - ARM Linux <linux@armlinux.org.uk>
- Moved Enable KASan patch as the last one.
  ---Reported by: Florian Fainelli <f.fainelli@gmail.com>,
     Russell King - ARM Linux <linux@armlinux.org.uk>
- Moved the definitions of cp15 registers from
  arch/arm/include/asm/kvm_hyp.h to arch/arm/include/asm/cp15.h.
  ---Asked by: Mark Rutland <mark.rutland@arm.com>
- Merge the following commits into the commit
  Define the virtual space of KASan's shadow region:
  1) Define the virtual space of KASan's shadow region;
  2) Avoid cleaning the KASan shadow area's mapping table;
  3) Add KASan layout;
- Merge the following commits into the commit
  Initialize the mapping of KASan shadow memory:
  1) Initialize the mapping of KASan shadow memory;
  2) Add support arm LPAE;
  3) Don't need to map the shadow of KASan's shadow memory;
     ---Reported by: Russell King - ARM Linux <linux@armlinux.org.uk>
  4) Change mapping of kasan_zero_page int readonly.
- The version 1 is tested by Florian Fainelli <f.fainelli@gmail.com>
  on a Cortex-A5 (no LPAE).

Hi,all:
   These patches add arch specific code for kernel address sanitizer
(see Documentation/kasan.txt).

   1/8 of kernel addresses reserved for shadow memory. There was no
big enough hole for this, so virtual addresses for shadow were
stolen from user space.

   At early boot stage the whole shadow region populated with just
one physical page (kasan_zero_page). Later, this page reused
as readonly zero shadow for some memory that KASan currently
don't track (vmalloc).

  After mapping the physical memory, pages for shadow memory are
allocated and mapped.

  KASan's stack instrumentation significantly increases stack's
consumption, so CONFIG_KASAN doubles THREAD_SIZE.

  Functions like memset/memmove/memcpy do a lot of memory accesses.
If bad pointer passed to one of these function it is important
to catch this. Compiler's instrumentation cannot do this since
these functions are written in assembly.

  KASan replaces memory functions with manually instrumented variants.
Original functions declared as weak symbols so strong definitions
in mm/kasan/kasan.c could replace them. Original functions have aliases
with '__' prefix in name, so we could call non-instrumented variant
if needed.

  Some files built without kasan instrumentation (e.g. mm/slub.c).
Original mem* function replaced (via #define) with prefixed variants
to disable memory access checks for such files.

  On arm LPAE architecture,  the mapping table of KASan shadow memory(if
PAGE_OFFSET is 0xc0000000, the KASan shadow memory's virtual space is
0xb6e000000~0xbf000000) can't be filled in do_translation_fault function,
because kasan instrumentation maybe cause do_translation_fault function
accessing KASan shadow memory. The accessing of KASan shadow memory in
do_translation_fault function maybe cause dead circle. So the mapping table
of KASan shadow memory need be copyed in pgd_alloc function.

Most of the code comes from:
https://github.com/aryabinin/linux/commit/0b54f17e70ff50a902c4af05bb92716eb95acefe

These patches are tested on vexpress-ca15, vexpress-ca9


Abbott Liu (2):
  ARM: Add TTBR operator for kasan_init
  ARM: Define the virtual space of KASan's shadow region

Andrey Ryabinin (4):
  ARM: Disable instrumentation for some code
  ARM: Replace memory function for kasan
  ARM: Initialize the mapping of KASan shadow memory
  ARM: Enable KASan for arm

 Documentation/dev-tools/kasan.rst     |   4 +-
 arch/arm/Kconfig                      |   1 +
 arch/arm/boot/compressed/Makefile     |   1 +
 arch/arm/boot/compressed/decompress.c |   2 +
 arch/arm/boot/compressed/libfdt_env.h |   2 +
 arch/arm/include/asm/cp15.h           | 106 +++++++++
 arch/arm/include/asm/kasan.h          |  35 +++
 arch/arm/include/asm/kasan_def.h      |  64 ++++++
 arch/arm/include/asm/kvm_hyp.h        |  54 -----
 arch/arm/include/asm/memory.h         |   5 +
 arch/arm/include/asm/pgalloc.h        |   7 +-
 arch/arm/include/asm/string.h         |  17 ++
 arch/arm/include/asm/thread_info.h    |   4 +
 arch/arm/kernel/entry-armv.S          |   5 +-
 arch/arm/kernel/entry-common.S        |   9 +-
 arch/arm/kernel/head-common.S         |   7 +-
 arch/arm/kernel/setup.c               |   2 +
 arch/arm/kernel/unwind.c              |   3 +-
 arch/arm/kvm/hyp/cp15-sr.c            |  12 +-
 arch/arm/kvm/hyp/switch.c             |   6 +-
 arch/arm/lib/memcpy.S                 |   3 +
 arch/arm/lib/memmove.S                |   5 +-
 arch/arm/lib/memset.S                 |   3 +
 arch/arm/mm/Makefile                  |   4 +
 arch/arm/mm/kasan_init.c              | 301 ++++++++++++++++++++++++++
 arch/arm/mm/mmu.c                     |   7 +-
 arch/arm/mm/pgd.c                     |  14 ++
 arch/arm/vdso/Makefile                |   2 +
 28 files changed, 608 insertions(+), 77 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan.h
 create mode 100644 arch/arm/include/asm/kasan_def.h
 create mode 100644 arch/arm/mm/kasan_init.c

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-1-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
