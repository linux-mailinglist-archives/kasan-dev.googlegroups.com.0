Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKG6QT5QKGQEV5N4BRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id E95A026AF4A
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:25 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id 135sf2614944pfu.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204584; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMwz+zV5WjbOiEWdaJsmhdKewYsQWg61HWG2H4qxP2JZEB+7xKDs4ZaLr022eel8ww
         m1WZPNJJ3BTGBVk0ndRGKHryjqmmwQ3+3x2V0ZnAmusXQTgojxeCibid/qNH6rcwhdZX
         YKAq+ZOeNGqBFbby9SNf2WT3pvtRQNB3ckeibc4jQNDiEG2ZbPv6CWabqOhEF3q/VTUk
         R1c7gvO3ZWev4gnNgQ/lwv7bFB/SN6+bAeg0Sx/JcLDnKge9oHv356mVM6oepE0FTX1b
         n0TiAKYMBodZLd1Uid4aAQ0M51eXUV0NMYQ9IrFTAPViI1oPchVrm8B+QlJKPyREd6Nw
         405g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=0ZpHxgKbneAFbJaUJdin057tH+UvpZs9Q/7BPFYuzr4=;
        b=lheCU+nf2GRDVF0GENuE2dFlVPEDYZcQ1j1L6IdHxqkTP3sV96Kbf7WdgyaGkE0GSM
         Jpr2Z8+RYVa9aLb0+MwfJMwQUrPI8Bjhgoh7q842Oj/mo49K2DOzv4mD7a1fezMaqqZ1
         LpCKm1EDgg+z/nLk2ncAllGaylAGrXDVRek3An5pAUZhQzmCS4vml9msyMhkO/M9rMDY
         6RbGH7Axb+Gunz6yJLbT9pWxbqeenfLGO0LxxZXti3cLlTravc3Nrwk7VIp+AigHT5H1
         6m8Fdfd607UzuZDheXZfgx7Fg3qlw/rMen2SQCdkY0tN7X/yTix1ZgN3dhrnx/iw1gkD
         efjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VNWaSIVT;
       spf=pass (google.com: domain of 3ji9hxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ji9hXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0ZpHxgKbneAFbJaUJdin057tH+UvpZs9Q/7BPFYuzr4=;
        b=oz2/cQm997Fva+5gQuVF0vhQQBRRzIflidX9T0XFF0QOOdMIJ3lA8FLcnx0GPNaAHE
         VdFey0l5u++Ktg2EajqrWRLivLNrNy3TyMreiy6/3Qiqpj3LHZ0Ubm8FvuezR6lenc0g
         cfMGsZJh+HqUX6JVIAeQBhMUcY1HVuHms1l0xT45Gi+umGU+oiXJWZzcrX9mm1xWXswd
         +98siwe5YpFyEvvoYuWNchjE4ojfPTWZDEKVmmkb5F3xjPR/TIWJbFihTnASDFPhKE5H
         mHK+MoUifEdbWv4fkYa1fIr6Yh1n8xcovuxKXnXmwkPwiBlfbcVnKmmraMdOxXyMShL1
         K2cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0ZpHxgKbneAFbJaUJdin057tH+UvpZs9Q/7BPFYuzr4=;
        b=o36rLpcPHcNxgR+xau4iV9wAC99boeavvEuFJQPQCXZXMfKWI+52kR1dv8xji6WIUW
         icWJZYeMvGUb8j3sUaxtxdG+h2uRmsxMS9iDmbkry5MoEn2jTgmUF9fFB3KGyxKEFs2i
         YD1URP0hSG0TAnB10T720gqwRXclDN44hwrRaxtaxUn90Dr5TQbwjoQUG8DdRwJRKz2w
         b0fdiBnLuGpJiKdAQhu3nEoYkoySChC0GG/Bp8s9YFwF2N/NdjrJzmc3kyVgws6HRvMF
         GjuSxN+CHyvABmPnu1SjZn8V+SaCRcC9pvld7MVrtgLn3GT0S9LAggcINh30q6YnT8RN
         ovSg==
X-Gm-Message-State: AOAM532lSHKxplLUmpaDyWHE5QWiALIBZfX61XicKj8B5kOlZguQNlni
	O0/YhjCRyTN6eyLaEC52/mE=
X-Google-Smtp-Source: ABdhPJyh7Aqv2ZBejvMQkDop73EGJcEREUCLdEulfzzqo98tx1L0rMNJ3+iAPUPtFvuB9WZfs4bxyw==
X-Received: by 2002:a17:90a:dd46:: with SMTP id u6mr1166050pjv.67.1600204584448;
        Tue, 15 Sep 2020 14:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4812:: with SMTP id kn18ls34474pjb.0.gmail; Tue, 15
 Sep 2020 14:16:23 -0700 (PDT)
X-Received: by 2002:a17:902:ba88:b029:d1:e5e7:bde1 with SMTP id k8-20020a170902ba88b02900d1e5e7bde1mr3482581pls.65.1600204583879;
        Tue, 15 Sep 2020 14:16:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204583; cv=none;
        d=google.com; s=arc-20160816;
        b=fKeVO8FgYRvFKXV5SCUiHxqf69ZNzeEH/351oG+wj6fJIpaGx2Xvq1RnagNG4KZERm
         zZpVyuSa/jv0IoVgzQ7OWkS02opZpIbi5l1XHARrHcI4h7EaHNyOzBJEdPRpGSIrzTo4
         XKF/ISfjCvf1L9m1O0okWLM3W6j5NRLGgIk0/Y/mArDmrzcCKUtvx61aoVTM9/xr9ekJ
         q6AIyonF4nohFEFOKST7oQKwRpC0Ydfq6uTlvWboTyp1sBTwJ4u7HQ591olEhW8ahGim
         VdrvQHhLXuoId4vIALSPblJyPvIPHBbVEwVWK0Cde3PfkQ0onFDkYgszBXgoiRrD+WUf
         yZZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=mLPMK4MCVaMfW1ExHIuH+/iSqevGe2FtNCbwS1lUn8o=;
        b=KA5VM+WbCVlhI0oqFzHWYZsv24SlCEpvBHdI6Y/4T0+z1h3UQvoLph0B+9C9d9jJ8v
         gyz5RShAycgDu61pgEtbvjUG0r1LtgjKj9BW9GvWBDcVBj2pq/OyfIePnySDZJxPmGXo
         noZZRAtZGcE+qvv4k60Vw/tIN7v/NdZS2Qde14bN437vxVhd+xsxC6SA5q8Yac/PV2ts
         NV7d82whWv11I3i+/RR9CIXOGxcF/ta2eq9A6KnxxRw1egMfDivXNrMLUFKRkozZG2S9
         EmMbnRsn2OxoqY+rIvrx+qQ/jvh4fyqxgEAzj6Z45dgwXpmj4XG9/J75Z5mLMNNSzAW7
         2koQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VNWaSIVT;
       spf=pass (google.com: domain of 3ji9hxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ji9hXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id r24si432845pls.4.2020.09.15.14.16.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ji9hxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id h9so3144063qvr.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:23 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9cc6:: with SMTP id
 j6mr3771581qvf.60.1600204582782; Tue, 15 Sep 2020 14:16:22 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:42 +0200
Message-Id: <cover.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 00/37] kasan: add hardware tag-based mode for arm64
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
 header.i=@google.com header.s=20161025 header.b=VNWaSIVT;       spf=pass
 (google.com: domain of 3ji9hxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Ji9hXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Andrey Konovalov (31):
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
  kasan: rename tags.c to tags_sw.c
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

Vincenzo Frascino (6):
  arm64: mte: Add in-kernel MTE helpers
  arm64: mte: Add in-kernel tag fault handler
  arm64: kasan: Enable in-kernel MTE
  arm64: mte: Convert gcr_user into an exclude mask
  arm64: mte: Switch GCR_EL1 in kernel entry and exit
  arm64: kasan: Enable TBI EL1

 Documentation/dev-tools/kasan.rst            |  80 ++-
 arch/arm64/Kconfig                           |   5 +-
 arch/arm64/Makefile                          |   2 +-
 arch/arm64/include/asm/assembler.h           |   2 +-
 arch/arm64/include/asm/cache.h               |   3 +
 arch/arm64/include/asm/esr.h                 |   1 +
 arch/arm64/include/asm/kasan.h               |   8 +-
 arch/arm64/include/asm/memory.h              |  14 +-
 arch/arm64/include/asm/mte-helpers.h         |  54 ++
 arch/arm64/include/asm/mte.h                 |  19 +-
 arch/arm64/include/asm/processor.h           |   2 +-
 arch/arm64/include/asm/string.h              |   5 +-
 arch/arm64/kernel/asm-offsets.c              |   3 +
 arch/arm64/kernel/cpufeature.c               |  10 +
 arch/arm64/kernel/entry.S                    |  26 +
 arch/arm64/kernel/head.S                     |   2 +-
 arch/arm64/kernel/image-vars.h               |   2 +-
 arch/arm64/kernel/mte.c                      |  90 ++-
 arch/arm64/kernel/setup.c                    |   1 -
 arch/arm64/lib/mte.S                         |  17 +
 arch/arm64/mm/dump.c                         |   6 +-
 arch/arm64/mm/fault.c                        |  43 +-
 arch/arm64/mm/kasan_init.c                   |  22 +-
 arch/arm64/mm/proc.S                         |  26 +-
 arch/s390/boot/string.c                      |   1 +
 arch/x86/boot/compressed/misc.h              |   1 +
 include/linux/kasan-checks.h                 |   2 +-
 include/linux/kasan.h                        | 110 ++--
 include/linux/mm.h                           |   2 +-
 include/linux/moduleloader.h                 |   3 +-
 include/linux/page-flags-layout.h            |   2 +-
 include/linux/sched.h                        |   2 +-
 include/linux/string.h                       |   2 +-
 init/init_task.c                             |   2 +-
 kernel/fork.c                                |   4 +-
 lib/Kconfig.kasan                            |  69 ++-
 lib/test_kasan.c                             |   2 +-
 mm/kasan/Makefile                            |  25 +-
 mm/kasan/common.c                            | 554 +------------------
 mm/kasan/generic.c                           |  33 +-
 mm/kasan/generic_report.c                    | 165 ------
 mm/kasan/init.c                              |  10 +-
 mm/kasan/kasan.h                             |  64 ++-
 mm/kasan/report.c                            | 254 ++-------
 mm/kasan/report_generic.c                    | 331 +++++++++++
 mm/kasan/report_tags_hw.c                    |  47 ++
 mm/kasan/{tags_report.c => report_tags_sw.c} |   9 +-
 mm/kasan/shadow.c                            | 509 +++++++++++++++++
 mm/kasan/tags_hw.c                           |  78 +++
 mm/kasan/{tags.c => tags_sw.c}               |  16 +-
 mm/page_poison.c                             |   2 +-
 mm/ptdump.c                                  |  13 +-
 mm/slab_common.c                             |   2 +-
 mm/slub.c                                    |  25 +-
 scripts/Makefile.lib                         |   2 +
 55 files changed, 1689 insertions(+), 1095 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-helpers.h
 delete mode 100644 mm/kasan/generic_report.c
 create mode 100644 mm/kasan/report_generic.c
 create mode 100644 mm/kasan/report_tags_hw.c
 rename mm/kasan/{tags_report.c => report_tags_sw.c} (91%)
 create mode 100644 mm/kasan/shadow.c
 create mode 100644 mm/kasan/tags_hw.c
 rename mm/kasan/{tags.c => tags_sw.c} (93%)

-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1600204505.git.andreyknvl%40google.com.
