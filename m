Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5OD3H5QKGQEDBEJCBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA87A280AEB
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:10:47 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id u11sf47920lfk.22
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:10:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593847; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJenejhuXgBqxEizRvZqtOG6QizQh+WcGfVwajoDxeOBAqeIzI/So388G7FC4c7RG8
         kx7wFVkkNrOPcZkbzBFjlSksTWjuqq4ECnysIo6ssWLSRf0FT3cpjmBgACfOjAzINFBM
         SV31EIO6LCsOye59ip5JdtryjKatoxYb+sDS35Pzi6X0va+5xCFn3uGG3yjFhXk/m/pc
         tMSqmASrsAAe5IXAC3KgTtdAwNu+6vWok0ItZ/nA96THON8jlvOY4DwkKJuHxv/l0LBk
         Wt5ZIxodcbwJcOKHgMd6830/5KX7rDfMRoI0saH6is+7acuxSqWkeTIDuR6lEp1m8iNh
         GStQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=4Bs5WJmbGk2qA3thAqFjG2lxSs82EjsNALHYmzMbvDo=;
        b=gNneNY8cyO4ol3hX66y+g/OwgW5yeaVUlUCfZ2VjSjEZ9NtpghqrQBN39e2bI+sx0G
         l3cpd7PQq2lKoUbt7uEB9S0Wpdz5T3x3iiVK3XiC/f9ZrZG5WvPHOCIGxYE3SP6+k4J1
         THqgEL2DEvCahZPuZKDZqH9lO7fw+1ecZ4KkZcIkTiNnov4DBLEIWdRgOrrX0iIcu0VW
         uc2K7ETJF8ORMawonq70incFwqOCNBOTQ0SYRypKYLEVIQFdedr6PmCF4TASrUkhoxgK
         D8cC90n8xL483GfxDv80fmqx1CNjTWRd3szXRWTNdVJuL4KvH4mHiDczbqA68LXKoLkH
         MFMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gkhXAnwV;
       spf=pass (google.com: domain of 39gf2xwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=39GF2XwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Bs5WJmbGk2qA3thAqFjG2lxSs82EjsNALHYmzMbvDo=;
        b=kmrCAw7IdVpMjLPCrOwcVy+vAzNWmMpdVyptsaxgMksDgDsq8mQN0GAvlbO8nv/BMv
         qwjWK7McfqnBi2ENi2LTaaarYCb//nomXRSJjPG9dczwWvls8V6SKXm2XY3YHqklEd0N
         LAHqmFFQ5467N9PqhqG2ER2fsuumbCREse6iyLRbd+dV0tYPaGY3m/I458kYGxb3O+eP
         +4h/WB9zxIxcX7VrhO10yEQ4W1SFY4M9eswVyMdrabxxsdprH3vxWXMoLgQKrvQhLidK
         clZ+sgHvOauB4UND30CyuJPAV10zn9XkJAIFIz7nj/icrDQydtuihWkuUteMuKQRRKtf
         9GlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4Bs5WJmbGk2qA3thAqFjG2lxSs82EjsNALHYmzMbvDo=;
        b=WFgdPy8PutKnq1dS1CSdJLlVBx9sSDdU3YoMWxx5aWQcBYTQ6zUm1tcX/UxJ1+ja9X
         W74VETINLjAMhjeOzpBgYPlL5YnY8rQvAAf1OOpXA2ah1t/iyIHKnrLQbTh3C4v8ULgI
         rZ1tPguGjtmLlPbM5T+VOZWdAWTK/X9qfNum9ERSEM8XyMg1aw3Xqf6IWdK13P/Zow+y
         vaN0u8wsE7GTM+mqAcbXhd4bAoG6W/9IRaKIasFT/rVASJ8UXwR7k2cGK9ebfTqz3FcZ
         /K9kutq2hHiAI4aS4Vly288ddE2gNkZZf2EEZstse+xqYR3P9vKqTH00cF7L0G0tkTLg
         cJNw==
X-Gm-Message-State: AOAM533Chk39k5tQXlaqsLkjAnBbPg/IhoOiWoEH1L4oT3TjZDe+BmC9
	fRGGIN8SWLYO0yAttVXvzoE=
X-Google-Smtp-Source: ABdhPJzFsOJmMLs0LwRMthFgs6mgykpbxfmt+XN1MCi+etiBY4xqzUVHXXftQp+YY8nSLxj5b+s1Qg==
X-Received: by 2002:a2e:5c46:: with SMTP id q67mr2587274ljb.40.1601593846197;
        Thu, 01 Oct 2020 16:10:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86c8:: with SMTP id n8ls1071096ljj.1.gmail; Thu, 01 Oct
 2020 16:10:45 -0700 (PDT)
X-Received: by 2002:a2e:b4a3:: with SMTP id q3mr2791524ljm.157.1601593844967;
        Thu, 01 Oct 2020 16:10:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593844; cv=none;
        d=google.com; s=arc-20160816;
        b=RLiV23dP3OxM4+aCtG4k6PkcJL3iIy9BpdDu0UGiwV4OsVCtcWT+o8qJpv+jzovBpb
         x3s/ExpPVWPoVSgEsAaXszAA01BOHLAEzK0BIzNOotmcvOuottQqYQsYPfA31PLmW0bj
         cyinz1pA2v65KOA8tw0tTrZiDVMyttDYWlRghCd5YlKuDZ5TXf6UyoCAU5zHlB5b6G/W
         MdOcJBNoFDH72orKhn7GYmKaNZicYSQ+c08Zew53TH3xYqRmLJ6iZdX/Stmpg1cwxC4Y
         SltBZSmtRqrVgDdahc2gic61e/ghpujb3l5BBHPR/IBl/jHXsiHStcwNf1i7uI6VkR5I
         CkYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=lu9/Flu3nAuPOzWFrYJmcrVEWseIH13ioDZBCovZl9s=;
        b=hjuoV4Kix0VthAzGi7S6Oqfai0GQgyUFiMfKkrqYqiJrn43AxaCotVgA042pHu3JTz
         p2EvpQIV+sPRcQerMmPIu6zJs2SNomxICHe8NZL4Ovt6uUL3Y8s2yDuEDsT/XGtmaeei
         33ZQh8gR5govivZB/Gp4G7RQyWYor+JGwsL7ZmLfqKBEmdKJpvq4ZqS62ZHKJWYOwf7C
         dMZPpUVr17cfwpZKM0Mmcc4/baw7f0vdu23SoLcB478C6RP4XYl+emrMhWUxW0iOWO2e
         xnNXm/eVBqguChCDfhzFUXCk1KPZRmegyfmIpi9ssU+A898V+kyT3pNzOngCWIS0iwZu
         UW4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gkhXAnwV;
       spf=pass (google.com: domain of 39gf2xwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=39GF2XwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x74si177492lff.12.2020.10.01.16.10.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:10:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39gf2xwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l15so122864wro.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:10:44 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6054:: with SMTP id
 u81mr2314460wmb.10.1601593844153; Thu, 01 Oct 2020 16:10:44 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:01 +0200
Message-Id: <cover.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 00/39] kasan: add hardware tag-based mode for arm64
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gkhXAnwV;       spf=pass
 (google.com: domain of 39gf2xwokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=39GF2XwoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset adds a new hardware tag-based mode to KASAN [1]. The new mode
is similar to the existing software tag-based KASAN, but relies on arm64
Memory Tagging Extension (MTE) [2] to perform memory and pointer tagging
(instead of shadow memory and compiler instrumentation).

This patchset is co-developed by
Vincenzo Frascino <vincenzo.frascino@arm.com>.

This patchset is available here:

https://github.com/xairy/linux/tree/up-kasan-mte-v2

and has also been uploaded to the Linux kernel Gerrit instance:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2700

This patchset is based on the v10 of the user MTE patchset [3].

This patchset essentially consists of four parts:

1. Rework KASAN code to allow easier integration of the hardware tag-based
   mode.
2. Introduce config option for the new mode.
3. Introduce core in-kernel MTE routines.
4. Combine the previous parts together to implement the new mode.

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [4] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] git://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux for-next/mte
[4] https://github.com/qemu/qemu

====== Overview

The underlying ideas of the approach used by hardware tag-based KASAN are:

1. By relying on the Top Byte Ignore (TBI) arm64 CPU feature, pointer tags
   are stored in the top byte of each kernel pointer.

2. With the Memory Tagging Extension (MTE) arm64 CPU feature, memory tags
   for kernel memory allocations are stored in a dedicated memory not
   accessible via normal instuctions.

3. On each memory allocation, a random tag is generated, embedded it into
   the returned pointer, and the corresponding memory is tagged with the
   same tag value.

4. With MTE the CPU performs a check on each memory access to make sure
   that the pointer tag matches the memory tag.

5. On a tag mismatch the CPU generates a tag fault, and a KASAN report is
   printed.

Same as other KASAN modes, hardware tag-based KASAN is intended as a
debugging feature at this point.

====== Rationale

There are two main reasons for this new hardware tag-based mode:

1. Previously implemented software tag-based KASAN is being successfully
   used on dogfood testing devices due to its low memory overhead (as
   initially planned). The new hardware mode keeps the same low memory
   overhead, and is expected to have significantly lower performance
   impact, due to the tag checks being performed by the hardware.
   Therefore the new mode can be used as a better alternative in dogfood
   testing for hardware that supports MTE.

2. The new mode lays the groundwork for the planned in-kernel MTE-based
   memory corruption mitigation to be used in production.

====== Technical details

From the implementation perspective, hardware tag-based KASAN is almost
identical to the software mode. The key difference is using MTE for
assigning and checking tags.

Compared to the software mode, the hardware mode uses 4 bits per tag, as
dictated by MTE. Pointer tags are stored in bits [56:60), the top 4 bits
have the normal value 0xF. Having less distict tags increases the
probablity of false negatives (from ~1/256 to ~1/16) in certain cases.

Only synchronous exceptions are set up and used by hardware tag-based KASAN.

====== Benchmarks

Note: all measurements have been performed with software emulation of Memory
Tagging Extension, performance numbers for hardware tag-based KASAN on the
actual hardware are expected to be better.

Boot time [1]:
* 2.8 sec for clean kernel
* 5.7 sec for hardware tag-based KASAN
* 11.8 sec for software tag-based KASAN
* 11.6 sec for generic KASAN

Slab memory usage after boot [2]:
* 7.0 kb for clean kernel
* 9.7 kb for hardware tag-based KASAN
* 9.7 kb for software tag-based KASAN
* 41.3 kb for generic KASAN

Measurements have been performed with:
* defconfig-based configs
* Manually built QEMU master
* QEMU arguments: -machine virt,mte=on -cpu max
* CONFIG_KASAN_STACK_ENABLE disabled
* CONFIG_KASAN_INLINE enabled
* clang-10 as the compiler and gcc-10 as the assembler
    
[1] Time before the ext4 driver is initialized.
[2] Measured as `cat /proc/meminfo | grep Slab`.

====== Notes

The cover letter for software tag-based KASAN patchset can be found here:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0116523cfffa62aeb5aa3b85ce7419f3dae0c1b8

====== History

Changes v3->v4:
(Vincenzo:)
- Introduced mte-def.h that contains MTE definitions.
- Moved __MTE_PREAMBLE in mte.h.
- Clarified which API is part of mte-kasan.h.
- Removed tsk argument from mte_set_kernel_gcr().
- Addressed several nitpicks pointed out during review.
(Andrey:)
- Move include <asm/kasan.h> in include/linux/kasan.h to avoid build
  failures.
- Don't move "select SLUB_DEBUG if SLUB" back and forth between patches
  in KASAN Kconfig.
- Add arm64 prefix to "kasan: don't allow SW_TAGS with ARM64_MTE" commit.
- Don't add braces when defining KASAN_GRANULE_SIZE.
- Make KASAN_HW_TAGS compatible with init_on_alloc/free.

Changes v2->v3:
(Vincenzo:)
- Use ARM64_ASM_PREAMBLE for asm macros.
- Rename mte-helper.h to mte-kasan.h. The new header is meant to contain
  only macros and prototypes directly used in KASAN. The rest is defined
  in mte.h.
- Update mte_get_mem_tag()/mte_get_random_tag() to used directly asm
  volatile() macros instead of calling library functions.
- Harden mte_assign_mem_tag_range() to prevent an infinite loop in case of
  unaligned size.
- Made sure that report_tag_fault() is executed only once.
- Simplify the mte code in __cpu_setup.
- Remove kprobes.h from mte.c includes.
- General cleanup of the code.
(Andrey:)
- Use READ/WRITE_ONCE when accessing reported in do_tag_recovery().
- Move .unreq mte_tcr under CONFIG_ARM64_MTE to avoid build errors when MTE
  is not enabled.
- Improve mm/kasan/shadow.c comment header.
- Clarify what is a memory granule in "kasan: rename KASAN_SHADOW_* to
  KASAN_GRANULE_" commit description.
- Rename (report_)tags_sw/hw.c to to (report_)sw/hw_tags.c and drop
  unnecessary rename commit.
- Adopt 100 lines limit for some mm/kasan/ changes.
- Align arguments for stack_trace_save() call in mm/slub.c.
- Restore comment before kasan_init_tags().
- Remove GNU headers from all mm/kasan/ files.
- Simplify check_invalid_free() implementation tag-based modes.
- Drop subsequently removed report_tag_fault() implementation.
- Add KASAN_GRANULE_PAGE and use instead of PAGE_SIZE * KASAN_GRANULE_SIZE.
- Move kasan_enable/disable_current() declarations to simplify
  include/linux/kasan.h.
- Drop dependency on CONFIG_SLUB_DEBUG.
- Clarify the purpose of CONFIG_STACKTRACE in KASAN Kconfig.

Changes v1->v2:
- Rebase onto v10 of the user MTE patchset.
- Only enable in-kernel MTE when KASAN_HW_TAGS is enabled.
- Add a layer of arch-level indirection, so KASAN doesn't call MTE helpers
  directly (this will be useful in case more architectures will add support
  for HW_TAGS).
- Don't do arm64_skip_faulting_instruction() on MTE fault, disable MTE
  instead.
- Don't allow software tags with MTE via arch/arm64/Kconfig instead of
  lib/Kconfig.kasan.
- Rename mm/kasan/tags.c to tags_sw.c and mte.c to tags_hw.c, and do the
  same for report_*.c files.
- Reword HW_TAGS Kconfig help text to make it less MTE specific.
- Reword and clarify Documentation.
- Drop unnecessary is_el1_mte_sync_tag_check_fault().
- Change report_tag_fault() to only call kasan_report() once HW_TAGS is
  introduced.
- Rename arch/arm64/include/asm/mte_asm.h to mte-helpers.h and move all
  MTE-related defines and some helper functions there.
- Change mm/kasan/kasan.h to include mte-def.h instead of mte.h.
- Add WARN_ON() on unaligned size to mte_set_mem_tag_range().
- Implement ldg/irg MTE routines as inline assembly.
- Remove smp_wmb() from mte_set_mem_tag_range().
- Drop __must_check from mte_set_mem_tag_range() as KASAN has no use for
  the return value.
- Drop zero size check from mte_assign_mem_tag_range().
- Drop unnecessary include <asm/kasan.h> from low-level arm64 code.
- Move enabling TBI1 into __cpu_setup().
- Drop stale comment about callee-saved register from
  arch/arm64/kernel/entry.S.
- Mark gcr_kernel_excl as __ro_after_init.
- Use GENMASK() in mte_init_tags().

Andrey Konovalov (32):
  kasan: drop unnecessary GPL text from comment headers
  kasan: KASAN_VMALLOC depends on KASAN_GENERIC
  kasan: group vmalloc code
  kasan: shadow declarations only for software modes
  kasan: rename (un)poison_shadow to (un)poison_memory
  kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
  kasan: only build init.c for software modes
  kasan: split out shadow.c from common.c
  kasan: define KASAN_GRANULE_PAGE
  kasan: rename report and tags files
  kasan: don't duplicate config dependencies
  kasan: hide invalid free check implementation
  kasan: decode stack frame only with KASAN_STACK_ENABLE
  kasan, arm64: only init shadow for software modes
  kasan, arm64: only use kasan_depth for software modes
  kasan: rename addr_has_shadow to addr_has_metadata
  kasan: rename print_shadow_for_address to print_memory_metadata
  kasan: kasan_non_canonical_hook only for software modes
  kasan: rename SHADOW layout macros to META
  kasan: separate metadata_fetch_row for each mode
  kasan, arm64: don't allow SW_TAGS with ARM64_MTE
  kasan: introduce CONFIG_KASAN_HW_TAGS
  arm64: kasan: Add arch layer for memory tagging helpers
  arm64: kasan: Align allocations for HW_TAGS
  kasan: define KASAN_GRANULE_SIZE for HW_TAGS
  kasan, x86, s390: update undef CONFIG_KASAN
  kasan, arm64: expand CONFIG_KASAN checks
  kasan, arm64: implement HW_TAGS runtime
  kasan, arm64: print report from tag fault handler
  kasan, mm: reset tags when accessing metadata
  kasan, arm64: enable CONFIG_KASAN_HW_TAGS
  kasan: add documentation for hardware tag-based mode

Vincenzo Frascino (7):
  arm64: Enable armv8.5-a asm-arch option
  arm64: mte: Add in-kernel MTE helpers
  arm64: mte: Add in-kernel tag fault handler
  arm64: kasan: Enable in-kernel MTE
  arm64: mte: Convert gcr_user into an exclude mask
  arm64: mte: Switch GCR_EL1 in kernel entry and exit
  arm64: kasan: Enable TBI EL1

 Documentation/dev-tools/kasan.rst            |  80 ++-
 arch/arm64/Kconfig                           |   9 +-
 arch/arm64/Makefile                          |   7 +-
 arch/arm64/include/asm/assembler.h           |   2 +-
 arch/arm64/include/asm/cache.h               |   3 +
 arch/arm64/include/asm/esr.h                 |   1 +
 arch/arm64/include/asm/kasan.h               |   8 +-
 arch/arm64/include/asm/memory.h              |  14 +-
 arch/arm64/include/asm/mte-def.h             |  15 +
 arch/arm64/include/asm/mte-kasan.h           |  62 ++
 arch/arm64/include/asm/mte.h                 |  22 +-
 arch/arm64/include/asm/processor.h           |   2 +-
 arch/arm64/include/asm/string.h              |   5 +-
 arch/arm64/include/asm/uaccess.h             |  23 +
 arch/arm64/kernel/asm-offsets.c              |   3 +
 arch/arm64/kernel/cpufeature.c               |  10 +
 arch/arm64/kernel/entry.S                    |  41 ++
 arch/arm64/kernel/head.S                     |   2 +-
 arch/arm64/kernel/image-vars.h               |   2 +-
 arch/arm64/kernel/mte.c                      |  89 ++-
 arch/arm64/kernel/setup.c                    |   5 +-
 arch/arm64/lib/mte.S                         |  16 +
 arch/arm64/mm/dump.c                         |   6 +-
 arch/arm64/mm/fault.c                        |  52 +-
 arch/arm64/mm/kasan_init.c                   |  22 +-
 arch/arm64/mm/proc.S                         |  23 +-
 arch/s390/boot/string.c                      |   1 +
 arch/x86/boot/compressed/misc.h              |   1 +
 include/linux/kasan-checks.h                 |   2 +-
 include/linux/kasan.h                        | 105 ++--
 include/linux/mm.h                           |   2 +-
 include/linux/moduleloader.h                 |   3 +-
 include/linux/page-flags-layout.h            |   2 +-
 include/linux/sched.h                        |   2 +-
 include/linux/string.h                       |   2 +-
 init/init_task.c                             |   2 +-
 kernel/fork.c                                |   4 +-
 lib/Kconfig.kasan                            |  66 ++-
 lib/test_kasan.c                             |   2 +-
 mm/kasan/Makefile                            |  25 +-
 mm/kasan/common.c                            | 560 +------------------
 mm/kasan/generic.c                           |  38 +-
 mm/kasan/generic_report.c                    | 165 ------
 mm/kasan/hw_tags.c                           |  70 +++
 mm/kasan/init.c                              |  17 +-
 mm/kasan/kasan.h                             |  64 ++-
 mm/kasan/quarantine.c                        |  10 -
 mm/kasan/report.c                            | 259 ++-------
 mm/kasan/report_generic.c                    | 326 +++++++++++
 mm/kasan/report_hw_tags.c                    |  42 ++
 mm/kasan/{tags_report.c => report_sw_tags.c} |  14 +-
 mm/kasan/shadow.c                            | 503 +++++++++++++++++
 mm/kasan/{tags.c => sw_tags.c}               |  18 +-
 mm/page_alloc.c                              |   4 +-
 mm/page_poison.c                             |   2 +-
 mm/ptdump.c                                  |  13 +-
 mm/slab_common.c                             |   2 +-
 mm/slub.c                                    |  29 +-
 scripts/Makefile.lib                         |   2 +
 59 files changed, 1742 insertions(+), 1139 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-def.h
 create mode 100644 arch/arm64/include/asm/mte-kasan.h
 delete mode 100644 mm/kasan/generic_report.c
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_generic.c
 create mode 100644 mm/kasan/report_hw_tags.c
 rename mm/kasan/{tags_report.c => report_sw_tags.c} (87%)
 create mode 100644 mm/kasan/shadow.c
 rename mm/kasan/{tags.c => sw_tags.c} (94%)

-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1601593784.git.andreyknvl%40google.com.
