Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7ES3P4QKGQEHPWXBHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 50200244DAF
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:26 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id x20sf6039807plm.15
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426045; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqvzqfdAn61fdayrviFvPtUcXiGgXhoK1gNk4V5Zi/QbwlInnAUyoCE6dwjq642Hhf
         JbZULdF64Ymzn3MHMCpB4UKGIIELoKjGYfcBoHCst6KRCRI1OzQhqhqwmCElsyFkabQ0
         u4/ynndXiX7oK+rVccPOsdL7AaQRUbtKS6P3rgSi1ZG0OFgcPytnvRNB7AoTx3PS5Rwm
         sF84D8YNXpBjITDYP81DBATGLPNwCGta2BqqQbQIIqwDqP6MWXD+aPjfNWEEW66SYmqQ
         ouC2b0TbO7HHG8qiiEk07VAD83Hnyx+1nt4g0lGuecgKKgdSIQFkIQsH02D5vyEGoyW8
         1ynw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=uFMjHxokM+OK6OVMbhsOJJWfldYWoTD7yWSLUCIEDos=;
        b=aY2XmjBlHo0Vc/pz6W9aND+i6zmttJzIwV4k7AhNg4Vjz45Xr7KMhtufJB0SuxbL6F
         ZVcT19908t2KjgkxFrPad0EJqZh1qYgT6MSDaNhR0/39nQ4hKojxeempAJh7EtepG/rJ
         SmrAagafICQYMVqsr7qFKZdqDksQPXAdv7oKIWdzQLjtC3cw61Vu/O1vOy8rk4RUO6Hn
         DsinqfC9HvoW7NqKyE2IdqBEoFVVwEUbbXFiMHa4JZwbIPdbp7MXiEBosrOOebISrIFc
         ftL6nzYlFdiJq5BAzTbZi//PIk9HylfZSAeMNegpZkMrEE2dKVjFmkS3IU+VEWQQq/2P
         4jpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xg76fkW8;
       spf=pass (google.com: domain of 3e8k2xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3e8k2XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uFMjHxokM+OK6OVMbhsOJJWfldYWoTD7yWSLUCIEDos=;
        b=fVDV9Lxup9sk5xQrJL1ul1vAtwltAP+AT1kFXqg+X+nWgDMWedpHac4I52pxJC2lV9
         EkM+DFjP3d32wgkIxMWpohIxjV+aMnuEcbxjTDpUQ8K9ObPUKyo80OHc70J3ljofjDd6
         et8ab6bfOCLyYqg8soFFJ9SFjBBM+IMYHYMDeM/7gDeKfKU0+U8E2WxryqQB/bjW6qiF
         B5tKfiMv+AsLJuS1UyUCJUzUctLEjSHOfcPPHoaA95CHxpt6c387bNThYggGYtZdnBOx
         gEaVBk9tikEdN6r56Xr9ksfc0gZ7j4jUs9nNz/BNfa+h2gIk/OCjV+3YVGEJXEPVRu96
         2K6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uFMjHxokM+OK6OVMbhsOJJWfldYWoTD7yWSLUCIEDos=;
        b=gzCuhYAKJSPkm6jruGX2FcSkSUdH74Cx20gzH+Ulq2j6CFE9HKHfc3/vRSUYiEgJNa
         5Riu6JMIsCBf1qg4Y22XfIjm7SiSxdaADYyGdHRasgvwnf4qgWvaqXyigd8EjdshyDQI
         8kHqR4RPgxQ2y804aFvMPX8cNHJ5WTw+ssfXTzW7H8lHkTdIR48genTux3rWggsvvqcb
         BPzMVu5a51aWv0ECSwdYcM2V0sQUJvnqZ3sqRojAI8nFqFQaHt2/1rxA4MlSJIe7pQjF
         oZl1MYCfTQ6/pUwZGQFemwdih4MMYYnyckRbmubzPM1uAbC0P4oRux74YEarga5/H+o9
         99Ww==
X-Gm-Message-State: AOAM533qn3jVnxuoGO4SyNNkxndAkUuPzgDJ2fhU0dPdKuuh+X60r9xQ
	zJs1r/uAJtzRQR1HiZL3K6Y=
X-Google-Smtp-Source: ABdhPJxSNurlVbBYa1nL96VDdKT0S/xhzVvDxN9U7QAY5jL7z0/qu2wdyUjwWoI7uMewD96rn5HZRw==
X-Received: by 2002:a17:902:b941:: with SMTP id h1mr2765752pls.200.1597426044819;
        Fri, 14 Aug 2020 10:27:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca88:: with SMTP id y8ls3919256pjt.1.gmail; Fri, 14
 Aug 2020 10:27:24 -0700 (PDT)
X-Received: by 2002:a17:90b:3685:: with SMTP id mj5mr3270285pjb.50.1597426044417;
        Fri, 14 Aug 2020 10:27:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426044; cv=none;
        d=google.com; s=arc-20160816;
        b=wFHNl14jfonNyVXgSxpQoW+FJEQXK1br7ACHCDGxZxXytCXRKKdtnu60OS1JcCEZi5
         0kKsO0U9CIif8WkjttndQRLSQpRN0MRmyjJ1qFD6OwaLYIo3u/pSXe7tYChhlOsq0TAh
         jdS86Na0JVVYZp9jSLkmY+JpDM3bFbT7C0zuwH9ZXxHCiwsQRrNk3Z4tdq9l2sAXZzhy
         +JxncS2Nm2vV0W8fiEgEfK+F2amMRkSVKW3lkApgGqUOJtjCi9qQF7e7wmRYI21nbG3i
         ekic5WhMr/Fuz0ehsykGI8/X6NJEIbqIcSV31GbhubjM5AptLOhMkPE3U2nuGDy0Sbm4
         8Hyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=0cNgcsyuYAwNS3ucnNThPdPKsO+dwuJKPiI6RmFliVA=;
        b=Y8HGc2PCGH2ZNJxNLSqXfnZJhykpiaLEeoyy5elQtkoKJmX48GBaqtqrvya9QUM+ru
         9+2I3+PUUiXUkQoYtOTmnhG9X9K4SuFRrhf1y+cRZy0tJKQubl8tsZjjFzNEKvUkm4sZ
         BYCwUbKLrVc/NVPYeP3hdMartwrm/+BWdDnZhxtpFAfqIC/Fe+CGYbSoIX1grXSZR15I
         SncBcu9B5b5QJN1GlujGMMlzB6YFCdaJs6xVYW5vjIBdd6D5qQ8QKviXikTYGuR8FeY7
         j7pGdOPT0XZWwdZs/1dX3eNxP/UJq4oX/ynGe4ftO3HMnkENlfvfGPqIVPDlM4UQ/ZqE
         ENAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xg76fkW8;
       spf=pass (google.com: domain of 3e8k2xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3e8k2XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id n6si449876plk.5.2020.08.14.10.27.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e8k2xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id h10so7490080qtc.4
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:24 -0700 (PDT)
X-Received: by 2002:ad4:4c0a:: with SMTP id bz10mr3506370qvb.78.1597426043462;
 Fri, 14 Aug 2020 10:27:23 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:42 +0200
Message-Id: <cover.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 00/35] kasan: add hardware tag-based mode for arm64
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
 header.i=@google.com header.s=20161025 header.b=Xg76fkW8;       spf=pass
 (google.com: domain of 3e8k2xwokcegkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3e8k2XwoKCegKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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

This patchset is available here:

https://github.com/xairy/linux/tree/up-kasan-mte-v1

and has also been uploaded to the Linux kernel Gerrit instance:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/2700

This patchset is based on the v7 of the user MTE patches [3], along with
some KASAN patches cherry-picked from the current mainline.

This patchset consists of three parts:

1. Rework KASAN code to allow easier integration of the hardware tag-based
   mode.
2. Introduce core in-kernel MTE routines.
3. Combine the two parts together and introduce the new mode.

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [4] with these patches [5] on top.
2. GCC version 10.

[1] https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] git://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux for-next/mte
[4] https://github.com/qemu/qemu
[5] https://lists.gnu.org/archive/html/qemu-devel/2020-08/msg02677.html

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
* Manually built QEMU master with these patches on top [3]
* QEMU arguments: -machine virt,mte=on -cpu max
* CONFIG_KASAN_STACK_ENABLE disabled
* CONFIG_KASAN_INLINE enabled
* clang-10 as the compiler and gcc-10 as the assembler
    
[1] Time before the ext4 driver is initialized.
[2] Measured as `cat /proc/meminfo | grep Slab`.
[3] https://lists.gnu.org/archive/html/qemu-devel/2020-08/msg02677.html

====== Notes

The cover letter for software tag-based KASAN patchset can be found here:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0116523cfffa62aeb5aa3b85ce7419f3dae0c1b8

Andrey Konovalov (29):
  kasan: KASAN_VMALLOC depends on KASAN_GENERIC
  kasan: group vmalloc code
  kasan: shadow declarations only for software modes
  kasan: rename (un)poison_shadow to (un)poison_memory
  kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
  kasan: only build init.c for software modes
  kasan: split out shadow.c from common.c
  kasan: rename generic/tags_report.c files
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
  kasan, arm64: align allocations for HW_TAGS
  kasan: define KASAN_GRANULE_SIZE for HW_TAGS
  kasan, x86, s390: update undef CONFIG_KASAN
  kasan, arm64: expand CONFIG_KASAN checks
  kasan, arm64: implement HW_TAGS runtime
  kasan, arm64: print report from tag fault handler
  kasan, slub: reset tags when accessing metadata
  kasan, arm64: enable CONFIG_KASAN_HW_TAGS
  kasan: add documentation for hardware tag-based mode

Vincenzo Frascino (6):
  arm64: mte: Add in-kernel MTE helpers
  arm64: mte: Add in-kernel tag fault handler
  arm64: mte: Enable in-kernel MTE
  arm64: mte: Convert gcr_user into an exclude mask
  arm64: mte: Switch GCR_EL1 in kernel entry and exit
  kasan, arm64: Enable TBI EL1

 Documentation/dev-tools/kasan.rst         |  75 ++-
 arch/arm64/Kconfig                        |   3 +-
 arch/arm64/Makefile                       |   2 +-
 arch/arm64/include/asm/assembler.h        |   2 +-
 arch/arm64/include/asm/cache.h            |   3 +
 arch/arm64/include/asm/esr.h              |   1 +
 arch/arm64/include/asm/kasan.h            |   8 +-
 arch/arm64/include/asm/memory.h           |   6 +-
 arch/arm64/include/asm/mte.h              |  54 ++-
 arch/arm64/include/asm/mte_asm.h          |  10 +
 arch/arm64/include/asm/processor.h        |   2 +-
 arch/arm64/include/asm/string.h           |   5 +-
 arch/arm64/kernel/asm-offsets.c           |   3 +
 arch/arm64/kernel/cpufeature.c            |  11 +-
 arch/arm64/kernel/entry.S                 |  28 ++
 arch/arm64/kernel/head.S                  |   2 +-
 arch/arm64/kernel/image-vars.h            |   2 +-
 arch/arm64/kernel/mte.c                   |  87 +++-
 arch/arm64/kernel/setup.c                 |   1 -
 arch/arm64/lib/mte.S                      |  41 ++
 arch/arm64/mm/dump.c                      |   6 +-
 arch/arm64/mm/fault.c                     |  59 ++-
 arch/arm64/mm/kasan_init.c                |  22 +-
 arch/arm64/mm/proc.S                      |   2 +-
 arch/s390/boot/string.c                   |   1 +
 arch/x86/boot/compressed/misc.h           |   1 +
 include/linux/kasan-checks.h              |   2 +-
 include/linux/kasan.h                     | 110 +++--
 include/linux/mm.h                        |   2 +-
 include/linux/moduleloader.h              |   3 +-
 include/linux/page-flags-layout.h         |   2 +-
 include/linux/sched.h                     |   2 +-
 include/linux/string.h                    |   2 +-
 init/init_task.c                          |   2 +-
 kernel/fork.c                             |   4 +-
 lib/Kconfig.kasan                         |  60 ++-
 lib/test_kasan.c                          |   2 +-
 mm/kasan/Makefile                         |  21 +-
 mm/kasan/common.c                         | 554 ++--------------------
 mm/kasan/generic.c                        |  33 +-
 mm/kasan/generic_report.c                 | 165 -------
 mm/kasan/init.c                           |  10 +-
 mm/kasan/kasan.h                          |  45 +-
 mm/kasan/mte.c                            |  76 +++
 mm/kasan/report.c                         | 254 ++--------
 mm/kasan/report_generic.c                 | 331 +++++++++++++
 mm/kasan/report_mte.c                     |  47 ++
 mm/kasan/{tags_report.c => report_tags.c} |   7 +-
 mm/kasan/shadow.c                         | 509 ++++++++++++++++++++
 mm/kasan/tags.c                           |  14 +-
 mm/page_poison.c                          |   2 +-
 mm/ptdump.c                               |  13 +-
 mm/slab_common.c                          |   2 +-
 mm/slub.c                                 |  25 +-
 scripts/Makefile.lib                      |   2 +
 55 files changed, 1653 insertions(+), 1085 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte_asm.h
 delete mode 100644 mm/kasan/generic_report.c
 create mode 100644 mm/kasan/mte.c
 create mode 100644 mm/kasan/report_generic.c
 create mode 100644 mm/kasan/report_mte.c
 rename mm/kasan/{tags_report.c => report_tags.c} (94%)
 create mode 100644 mm/kasan/shadow.c

-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1597425745.git.andreyknvl%40google.com.
