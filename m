Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTGFWT5QKGQENNMHX4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 299E0277BBC
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:50:54 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id j4sf333557ljo.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:50:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987853; cv=pass;
        d=google.com; s=arc-20160816;
        b=sxwqw/kTQcXzuehZ/5EBM0/KEXPedADbne/ddhXDLmb2b6MOAKRwq2whbWGdhHNulc
         lJsFQn69Xo1Y5rsHF+Liu1ErJje7yD9P030FGNGtmSTQIIUW19zNibtUPq7t6M+LytCC
         1NYoCOUarUpFD5XDFcUvYtg69N4doDXPk7saab2Wy49SSDnDxmvGSP7Mr7KFngsIHJH/
         n9tLdaduWgSJbotHVsJa2udKrDzChqpL4ZAFFxYb/5s1vMBxfBzY9MDV4wEId9JEjvc9
         zAzfd9f3f9UVLAuNq6qBKWpw7OWq/VN8vGPz7K8pELo7XvsX/c0X1GItFIgMXHRkDI9Y
         HL4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=M3qhZBEcKzY3NS1NGcqjKDqWri/J3jrk1FjpxJpOhKk=;
        b=rkOwj3Mo7uuY9m/SXghrckv6F8T61PCABJKvROTg9jh/VMu3uqbCaa714FEa77fbJo
         MaWbufeDSR9tpengSSvfIJrTzimFV7LIJlzVOlC9RPnWCJ80humo2Vqez+CMUhC90gDB
         2nOzfFRh7Cqcz9CXZV63a0psvMnIUh/8cCC9EAtJ6Sjp0+6gBYkh/paFSfCyW8NiCeJu
         mxje+ICX4SZOuKcq6u9p+CzzPI5jXM+H57kE4hd5snJyc+IUjSu59UbONmEuWq6mnffr
         Fc+nLmlX6cDaEKIrwB0fKVZcXh07zFOea48uUOesDjPktT/HUgDB9/kHfYSSkXPd97tB
         9NDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LmZenUpg;
       spf=pass (google.com: domain of 3yyjtxwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yyJtXwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M3qhZBEcKzY3NS1NGcqjKDqWri/J3jrk1FjpxJpOhKk=;
        b=jpo/pS8oJW5aeeq7jleJfx6LMVHV7WXpoyV7eaowOWWPXda7wvDJ28zH0CDoKPsrHn
         8Z+EMYmF9LD7zikf0i2JtBLSelgf4ZZ9R23VdLvacEpfo/D1i59P7aWkI0BOOqtxa8A5
         0Nscti/ZNl1efmCO0N8IE4dCenNZITf1iVr2DRoqReNLdDWgs15SB38CmnAQJ5l1rD30
         kplZby1nmbe/cVRfspXZDAkkJa4/vNmMmIcjugqYsNjDAPbb/KLRL0prOJs773q47L2H
         3FFs4cB6pAz8BwNdIE1xpzCVAv+ieVCAqnYNTkKHUfW/yG40BEqsAh9K05VQB0VbTuYh
         /2fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M3qhZBEcKzY3NS1NGcqjKDqWri/J3jrk1FjpxJpOhKk=;
        b=X4kILFYpzbNFAI2NK+dviQDGcunGelsOW75E3YmHpSw2Ue+0P75HLrXnzqfCXPSLim
         /26/Twgi8TcdVuDtyzXfVSV5zF6V6tvphXCrD75jMdWsBdpEDDx8WsH/TmEtdVQS4suB
         U0/HfulGcO32gu3/JaIdN5hRCfotPkLQOFoY4Vi1vY7iX3AirBzOh5dFXI5USIIH/TKJ
         UatzlkE6pU7R/hCD9F/pNyHF28L/KM2gDk8UD1+8SwKYDvt8MXjGaltl53SJUroZ0QGs
         gp6u3Ylkuehw7zqPKRAXynHj6D4Pi5zcsoKk64MLqDeBK1VYz0uOY5W+j71yZ2SaK7+M
         b9XQ==
X-Gm-Message-State: AOAM532SVKONPtdLUVSyTQqp4Rhik1Y0OJmZgD28YvAP87rU34LIMe4+
	wSJiMv0x781Kc716ozXaudU=
X-Google-Smtp-Source: ABdhPJxyBS7Olw2c3fpUGXaXcjQzSO71O6VZeZdyMwmtk2q7J/fcU2TSrNwMdMeo1SlnbANpx0hSqA==
X-Received: by 2002:a19:b97:: with SMTP id 145mr314470lfl.193.1600987852832;
        Thu, 24 Sep 2020 15:50:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls89696ljn.9.gmail; Thu, 24 Sep
 2020 15:50:51 -0700 (PDT)
X-Received: by 2002:a05:651c:1284:: with SMTP id 4mr411192ljc.76.1600987851876;
        Thu, 24 Sep 2020 15:50:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987851; cv=none;
        d=google.com; s=arc-20160816;
        b=yBonR02sTFBAvXUXzQYTRJwojNtVhVaqiQph5KvbacdZKf5U4fFRrfIdCFoM0IZ7rf
         RPFIjI69t2BDWDFFxNXBLUzTHLnB9VgNLHTupaO8nu6i62lHEPu9eFIOD5P2hXw5vgVo
         RxVCYMs4DgZMl1sfawhaN3dkrLSNGiuzauryyVZYFWsgfNv6qnfcZXeK5CfCa9Sn9KeR
         U+XNIjgmYiifGFZ+WyxjAAD2rNCrsVTfpiF2vt3Sb1+DyYFw2p6Q134UQtL/UdC9FUkO
         Uh7mueeyqeocRVTEDe0ZUDCZKcAtrM18XA9eGyV1qnBDueQjxD4x3MIVNEWbH89Ps7zX
         jNqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=cj4m+M4mWXPK1dzdePVpRn6w7cYtGN7aEWc/ALOq0jk=;
        b=kMPkiE0vAXs02X99cGqCBCcp7QrDPD5oaLIfRV7U+zjSGlQ2SbriKM5a0AAZrE9x/n
         /Xpk0ZF8N6Sr3cINk8jm/r8CDb05I2fUswVa5e3ZoE0b902bKJhWEPXzL0k5D7Ap2wLd
         ZbLljflgSkxwQwbU7M4ekfgtv5Mowf6rKUmgIkoxcSsDAFfLHLjwr138832M7xhXLdLi
         FT8HCDkJEgbcqqZ3TrgHoRi3LxcxOmSmaw15sxOqqLkB7w1BEpLv9MsgbRta8kdITUXc
         oreWwtDUTksb/l/mVk7fp6Ze4DJUwQZZJZL1W0J4V4SAGQ6Th4a7mCC3GqD32tR5QECf
         Ucrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LmZenUpg;
       spf=pass (google.com: domain of 3yyjtxwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yyJtXwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r13si22491ljm.3.2020.09.24.15.50.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:50:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yyjtxwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s8so281590wrb.15
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:50:51 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:21c4:: with SMTP id
 x4mr848322wmj.107.1600987851123; Thu, 24 Sep 2020 15:50:51 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:07 +0200
Message-Id: <cover.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 00/39] kasan: add hardware tag-based mode for arm64
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
 header.i=@google.com header.s=20161025 header.b=LmZenUpg;       spf=pass
 (google.com: domain of 3yyjtxwokccymzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yyJtXwoKCcYmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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
  kasan: don't allow SW_TAGS with ARM64_MTE
  kasan: introduce CONFIG_KASAN_HW_TAGS
  arm64: kasan: Add arch layer for memory tagging helpers
  arm64: kasan: Align allocations for HW_TAGS
  kasan: define KASAN_GRANULE_SIZE for HW_TAGS
  kasan, x86, s390: update undef CONFIG_KASAN
  kasan, arm64: expand CONFIG_KASAN checks
  kasan, arm64: implement HW_TAGS runtime
  kasan, arm64: print report from tag fault handler
  kasan, slub: reset tags when accessing metadata
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
 arch/arm64/include/asm/mte-kasan.h           |  66 +++
 arch/arm64/include/asm/mte.h                 |  19 +-
 arch/arm64/include/asm/processor.h           |   2 +-
 arch/arm64/include/asm/string.h              |   5 +-
 arch/arm64/include/asm/uaccess.h             |  23 +
 arch/arm64/kernel/asm-offsets.c              |   3 +
 arch/arm64/kernel/cpufeature.c               |  10 +
 arch/arm64/kernel/entry.S                    |  47 ++
 arch/arm64/kernel/head.S                     |   2 +-
 arch/arm64/kernel/image-vars.h               |   2 +-
 arch/arm64/kernel/mte.c                      |  85 ++-
 arch/arm64/kernel/setup.c                    |   5 +-
 arch/arm64/lib/mte.S                         |  19 +
 arch/arm64/mm/dump.c                         |   6 +-
 arch/arm64/mm/fault.c                        |  52 +-
 arch/arm64/mm/kasan_init.c                   |  22 +-
 arch/arm64/mm/proc.S                         |  24 +-
 arch/s390/boot/string.c                      |   1 +
 arch/x86/boot/compressed/misc.h              |   1 +
 include/linux/kasan-checks.h                 |   2 +-
 include/linux/kasan.h                        | 104 ++--
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
 mm/page_poison.c                             |   2 +-
 mm/ptdump.c                                  |  13 +-
 mm/slab_common.c                             |   2 +-
 mm/slub.c                                    |  25 +-
 scripts/Makefile.lib                         |   2 +
 57 files changed, 1727 insertions(+), 1137 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-kasan.h
 delete mode 100644 mm/kasan/generic_report.c
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_generic.c
 create mode 100644 mm/kasan/report_hw_tags.c
 rename mm/kasan/{tags_report.c => report_sw_tags.c} (87%)
 create mode 100644 mm/kasan/shadow.c
 rename mm/kasan/{tags.c => sw_tags.c} (94%)

-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1600987622.git.andreyknvl%40google.com.
