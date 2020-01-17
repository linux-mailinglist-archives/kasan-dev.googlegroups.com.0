Return-Path: <kasan-dev+bncBCH67JWTV4DBB5PURDYQKGQEIDJA7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 797C3141451
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:51:34 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id c16sf4810775lfm.10
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:51:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301494; cv=pass;
        d=google.com; s=arc-20160816;
        b=PHe90djXSwWEEjZAaKKnaXoA+i8x4fxrmOwIzW+M9oWIgZ39XoneCFlX8rkcgUKFWi
         EwFRd6QvcfQHVbRSHxE8QD4txUD0GbfEWrEH1O0ynl+kUak1RueUfw+n8UXAvMOZVXMf
         udlYqRRGbORqhcvcD9Pt/KJtJ6L3YrR7gP9MM8uiz9epSgUrpWo8T4/wxzicxhUZ+sIy
         coCf5cMmYFYPp1ELIah1yXNFUDpWUawFEpc4mQrjG6C4ounDe7GNzmOjtGQkV5vdC2A8
         lfQri8PDTDxXZ9WRtavapi2AkCmf0xToOmvK8H+dkoSZDZ/492iCbOgTjMypRwjt20Wl
         4O6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=++/G9yHrxJ7uSvIQSxs+Hzn6/p8TigazqzjYvEZ1iU4=;
        b=eMmg+2tbchXXajT8AOiA80XtLrZL0l7f8QkeSfjgMKWN69+99i/PK+o6GTa1vw9Qtn
         yNRbECa0FwmX5BM0a8OfxW0t0G+KENXYvT18gIz3wcL0tkOrD01VDxNE+w4576N4uKi0
         T1YrpqZWWE3oTJz4BME86mfiBRdtMZ9OpWCyIbgeRUJEb9mqaaxZB2wR8eWyBc/HTAFo
         m/IjY70jIk4tlIXmmOcxElrrISRMiUAv60NnIb2Za1kyIqH7HUzufQigrD5xv6S07Ibj
         X/5PhgdSI8bK/kCLaj8al5pcBaNBFlsqsxDaE56FH88O4lb6zfgVd9qMy5wXL0zCdFRb
         0IJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VYiJCWdn;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=++/G9yHrxJ7uSvIQSxs+Hzn6/p8TigazqzjYvEZ1iU4=;
        b=nK21spSxU7kbzMy/bja3T3BVvpdg+V/oqvmUJSDRw5oNlUWR4Dflnqw+tGSR3XOZKZ
         OUkgfd3cLaJy7nHL4+x9MNi01Ql3kcekmKLF/RvPBklAgpq8hJG4tXKt7V5D8nDVKqMj
         t7TIuA5EPV6f4xnAP21p+PGWxcQ8hBeYQc5emrz3F/oeH9ZX0mNqwfS625183xXsDSB8
         i+BfmZUsFc0vIQeRH2Iwmk80ye1V4/JXgGiBkgUZWC7GZmbSLTAzhzKk+LcSHA9LunNb
         jaMovJGtX2s5ff5zu/doe9mifZGvtDR+JxOo2mivSJqZu0r9T844Tvv6YlnumSLemM9e
         ScWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=++/G9yHrxJ7uSvIQSxs+Hzn6/p8TigazqzjYvEZ1iU4=;
        b=VCzhkhrzghYE6qa7hHQIya0bJuZW1rAJtc64s4Pr3ZtzgO/FOdVt/wlaIz3thjXTWh
         gaYiPTVytSSLN62/lP387l5Sgghp97CUBVJp9Z9NgmH3qJTMiqeIsJSXA1ylzgkQZvMM
         f/H2vSfOvZZaZc5SeK4j35qsQ/u03Ed9fv+ogVbd07+757OyygTW050tUwfB8ClOgVKb
         tmZJc/nFd4sKYu7wIt+6uBsb8A1fK0XBMzEBZJpg5isuiD9n+fEP5S4OmXNLmh+UcsiW
         KNWepmILyGVEFCy+7QoyNfgLx8urd37V1TxFhHW4AxPLhu1nQW0GCVTH2vMLWDtsKrxF
         dRrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=++/G9yHrxJ7uSvIQSxs+Hzn6/p8TigazqzjYvEZ1iU4=;
        b=Q4Hbec3ia/n8D9w6Ees66sdkXTqQeNdJpqCXEbMcdJSEFuGtb9s3vfzbQsL2NvwRcD
         SRCaRp+fAVWWsiQzXaBQNQswpY+B9jDOSodi/NZy7xvDBERYPc7BPS02oANSWKgWCeJG
         ZV5MM2URXw6IUqo3NXor+Y39dTXZ8aqTMI6k+/AanszVpM9gR/x/ixRXL/7xHqKE/6ol
         ynlXjOABpzuQ3ALLcTBz7NuO46ImpemVq8rfYBiviOiPSkIDrzMvJLauYGPZTf8UvBCo
         80FChT6GIYILZXazEr6HSF5iR5i+Fi0QfBGvP/YAnej6tqM73zF4JfZV2xbn3ol/KBNq
         4XIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU6h+CpchfL0JUeyLvuIHDr784GqXrpKKbQv9OQrP8BLxtFIcNP
	vYYs7YHPg7JTB8KAoyYjc68=
X-Google-Smtp-Source: APXvYqwplQA8ZZn7pPgQHl81vM06JiClT0BfJ2orW0wabGRUZMn1ekSPNrEuwWmXSpteKzZhJTWxaw==
X-Received: by 2002:ac2:43af:: with SMTP id t15mr6777952lfl.154.1579301493907;
        Fri, 17 Jan 2020 14:51:33 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c8d6:: with SMTP id y205ls77478lff.4.gmail; Fri, 17 Jan
 2020 14:51:33 -0800 (PST)
X-Received: by 2002:a19:c148:: with SMTP id r69mr6782664lff.142.1579301493071;
        Fri, 17 Jan 2020 14:51:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301493; cv=none;
        d=google.com; s=arc-20160816;
        b=0Vll8MA2F/x0TWB2gHm/lPFy3RWMIqkqEPG9Gqf0x5tgt4XUiab6NnaZN/2OgZUHcI
         njAstSO0bte/HZp6JFiR7+iT542m/S/pKaxDEpCP6BxE5spbD9dW+7/SSNdBfY0Q2zg6
         0YmUPGaZvApoM/AnOwIBWSNTAndcmSUpEMq4CdbjVem04EQRc9I8dmqU2sOj8mk2b4JM
         fSQK8KpClebOVldBZuEAVdThZeFvyTtPQyPKi9GwSqPq0V5EHDAuGixN94B+cfORfXdN
         iXVJnbb6DHHf7+gU0xPpPnMjMOjqjWsKmBDe/qY8RHN+OCQyre4xkgxzl/Dlw2qs/wyd
         /Uuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=rB/I9wTlZsluZ1pWX0XXmWdx5P73UU2DmRV579b2vuw=;
        b=zy95mGfudzvmzsFYjMwT2gVjbd8EXrj2I/5Ede86zOT7ht7sn/7lZMk4zKLiqHoL8H
         gNgvRmKSXP5YbFSOUAp2MfefuVwAViEJbLS/GfRkp6ylD+FS/hy+S6YVxbHRlTCv0X7j
         Vku3fSddfXE/P1oV2hiJJfYTiUUAGEHLL8aYVqdQxZAnyH5g/KUNbpKlT1BIgG0qvqvl
         yi0K6Q/JWmFySAJWGRzqivvbLxqpINwVIySuBTM/VeZ5pPx4Z7VlsumIwjw4CqOPjkaS
         U6ZX2P6c9EDHX7SeZMnBm4MVybBINXc/nYXu0AhXYOa78nza70tgGtRJcUMUhtvvucZE
         gm+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VYiJCWdn;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id p20si1396337lji.1.2020.01.17.14.51.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:51:33 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id q6so24106963wro.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:51:33 -0800 (PST)
X-Received: by 2002:adf:e40f:: with SMTP id g15mr5286688wrm.223.1579301492262;
        Fri, 17 Jan 2020 14:51:32 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.51.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:51:31 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
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
Subject: [PATCH v7 0/7] KASan for arm
Date: Fri, 17 Jan 2020 14:48:32 -0800
Message-Id: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VYiJCWdn;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::444
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

v7 - v7
- add Linus' Tested-by for the following platforms:

Tested systems:

QEMU ARM RealView PBA8
QEMU ARM RealView PBX A9
QEMU ARM Versatile AB
Hardware Integrator CP
Hardware Versatile AB with IB2

- define CONFIG_KASAN_SHADOW_OFFSET

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
  ARM: Enable KASan for ARM

Florian Fainelli (1):
  ARM: Moved CP15 definitions from kvm_hyp.h to cp15.h

 Documentation/dev-tools/kasan.rst     |   4 +-
 arch/arm/Kconfig                      |   9 +
 arch/arm/boot/compressed/Makefile     |   2 +
 arch/arm/include/asm/cp15.h           | 107 +++++++++
 arch/arm/include/asm/kasan.h          |  35 +++
 arch/arm/include/asm/kasan_def.h      |  63 ++++++
 arch/arm/include/asm/kvm_hyp.h        |  54 -----
 arch/arm/include/asm/memory.h         |   5 +
 arch/arm/include/asm/pgalloc.h        |   9 +-
 arch/arm/include/asm/string.h         |  17 ++
 arch/arm/include/asm/thread_info.h    |   4 +
 arch/arm/kernel/entry-armv.S          |   5 +-
 arch/arm/kernel/entry-common.S        |   9 +-
 arch/arm/kernel/head-common.S         |   7 +-
 arch/arm/kernel/setup.c               |   2 +
 arch/arm/kernel/unwind.c              |   6 +-
 arch/arm/kvm/hyp/cp15-sr.c            |  12 +-
 arch/arm/kvm/hyp/switch.c             |   6 +-
 arch/arm/lib/memcpy.S                 |   3 +
 arch/arm/lib/memmove.S                |   5 +-
 arch/arm/lib/memset.S                 |   3 +
 arch/arm/mm/Makefile                  |   4 +
 arch/arm/mm/kasan_init.c              | 302 ++++++++++++++++++++++++++
 arch/arm/mm/mmu.c                     |   7 +-
 arch/arm/mm/pgd.c                     |  14 ++
 arch/arm/vdso/Makefile                |   2 +
 drivers/firmware/efi/libstub/Makefile |   3 +-
 27 files changed, 621 insertions(+), 78 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan.h
 create mode 100644 arch/arm/include/asm/kasan_def.h
 create mode 100644 arch/arm/mm/kasan_init.c

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-1-f.fainelli%40gmail.com.
