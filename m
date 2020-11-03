Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYFUQ36QKGQEL4PIIVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 393B02A4D9F
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:58:57 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id e31sf3059267ote.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:58:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426336; cv=pass;
        d=google.com; s=arc-20160816;
        b=kEf2+l2Em0/1zORnxPRgX3zby/gnuNx6ShonpZu9vcMi7ItixwSNLRwG5lZppbcqow
         yl7wPQn5QB+t5AmJxDbO9eho9OdzfPP/re7/JFfI4HN5o4FZEUqthkIa84OV4E+k2yfN
         E6SBI7PUYHllMHJS9rVX5/HLxowFJO51yUZVbJhPm31rJrKftoybIypePKSKbWfE7XRA
         dkagR4bNd8qtM4YPPzax28K/3p0HbwQyedoR6K9lPglcsLuoNzw2ou16cUgp+KTSc+Jh
         cD5DPzRmH/Fe1JamBwsiY8Gz0t/GZJz8k1AIf01/PBRuqBwcpAP0B9Mmz2OyrfbWuE2I
         GaSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=wU+aotFiE2Shj/tv1kVqeBadBQCl1Q+3epy8GLJiVbM=;
        b=KKKIfmeKpVpmrttcre/ni81pull3KbXFgHwRi7sjVvOfEjJqllZ1V+PX0rj2Rrq+d8
         NpKOBVB1L7VkEVzSL1eNw2+iXgcpm0dCvtcrMLSBg53Ko6nQSTDXCpz8LQG3mder2sKd
         hfb0sS5VtpRLAYkFSXZsAFbpyhn8OyuFFst2TrtpJAdcoT7y8nNL9GwflNxn5mqZA2pE
         JJctcXdHKjf1dd6lH/OD3VNkCu8O5MqX9s1ESP2WWbcxsOGCKkzOAIkNhT6ZN98Iw5w6
         7FyPjQ2b0c+2GucDqQbu/ZqVyD7uDgflgRl2N28+PQqTsrRIRL8rSTUJIG+XrovEUv9u
         I1iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MPs5H9K/";
       spf=pass (google.com: domain of 3x5qhxwukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3X5qhXwUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wU+aotFiE2Shj/tv1kVqeBadBQCl1Q+3epy8GLJiVbM=;
        b=oSsmnD0nm5Da5nJo5yNhKwV3OytrqKHdlyeSaE1YIFwFcfijoYz0mZyVUnbXHSwRp1
         feOkbjKmJHiBvyQRiVbbuB3b3xa4HoJz0uqlJImow0pgjyI3QHi51C1Psw464hDpzgBm
         28riaLvU9c0FQqmZWmeK1rx1w4UEkBSKAj4EVPqb+zDv0kzPEkUcxdTJcAO4/bJHsA8y
         dKBdTYrJaDAveiAIu5UjLyH3jmcyiCWQ1u1iyCNISJN7Cupd9v0QL0JcQKDLN7TUbxaR
         5J7SR7DqlKoKt5/pNR/gUnG6wsvt7pZLKReifAVq2OdtaYkyFiiN4oAspzP/gfXVWn3m
         SqWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wU+aotFiE2Shj/tv1kVqeBadBQCl1Q+3epy8GLJiVbM=;
        b=V79Ex0/nVWH/GwzrIkB4NqKo4BC1gDYftyvqdVBM63oMeZWMqx832zrXtgjIL4QrMj
         ao0EEQui1SAblSEAor0XgP3Ym4moAOQfEscaa8nKtSI/CFgJpdj6z3g/JB3uClu8jRFp
         wrvLjjbpJ8MsXJkTqeizsWiuGCU5dxlmn2UItCSssoWlTpHNvqpVUP9dUwIRalDFZLCo
         Ucd34EkVmZpv+LIABbzB8QqUiaS/acJtFy+CeAqF8D6jBTufiG2dXVnS9sQes7s14Euy
         OoKjEpCqfeaVlbqdFD6j9spjE5GbBuAHqpG2XLK2tdJsNyQWEbO8NSe79W/COQchemTC
         nuXQ==
X-Gm-Message-State: AOAM533t3xtFzHd4Xz2m4XhdN5XS2RPd7zlqLdUGhlbI0NzLSjIMEG4R
	9f457FvldmeGM3n//05Ktnw=
X-Google-Smtp-Source: ABdhPJycpj8G5d7T97hLTC9WD3V4T1gBhFjDWF2tp1JCIi9XKMZLFWnxa6D/IYO6ci2/LUPRh3rYAA==
X-Received: by 2002:a9d:7385:: with SMTP id j5mr11884837otk.252.1604426336151;
        Tue, 03 Nov 2020 09:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:de07:: with SMTP id y7ls177879oot.7.gmail; Tue, 03 Nov
 2020 09:58:55 -0800 (PST)
X-Received: by 2002:a4a:2843:: with SMTP id c3mr10854967oof.3.1604426335708;
        Tue, 03 Nov 2020 09:58:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426335; cv=none;
        d=google.com; s=arc-20160816;
        b=UK4PnTLfo5heZPqGaaDdLY7ATjtryWfBeDcG+fiGszRssmvM1l85hf87AajqHk4rju
         lLVFVWTdP3TBReOGHGB4ZNDryqXTHh8H/b0ksRDYTdiXRDpBo/rqmUAnwjtkrDfWNSLg
         nd2rgrqyQehXm0plAOjvnaiQyA2TbOJIhcEar9NHPYfRQkpwfqRkd4sfuJhDdJg76MYV
         br4uWUkJzOWfChS6UmuaIWNqSC0KykDFvMYXY5U9ndGHMsPricLG6wgYbaGLuNUQTeDJ
         j6Ecpa+zpUg1LIvAzrkP6n4sI12KY4UP5zGTa6AgsIqNvhFbqcg/GzIGbQPC1exJEYWq
         /QMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=GGWgvoZY910z090vjaD/trTDnHRiD2bK8G9Zkm0OdaQ=;
        b=oja7ONKLumaOcBeGBbCyLPk7km+an3A2QU/8vabiQISF1jFz1pO9YPINEhnWG4lRTI
         eWwmXictLNbDpEaBhmilih5xySS9Me0EXmuV1ylxS/s+CtJdzXrUih/C1ZLelCnkWapb
         0mtedf6nBCOv4UGPGE7qwzu/DqX0nnHRjhkK0qQlbH4fT/NnnhWISMP70Nw9RsvWWzpO
         QQ7a6kESm9dUeynKpPcJL4dJoNfTD+7ydGGR3NBb56LGi/PSbtbpI+FyCc04Pz61gFdc
         t9S8TFdsvIK9VbFOJYFpMUbL00BGtPADYwvXj2aBdA+KUdeXEHFu/5n1uZ95DrMEGbv+
         190A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MPs5H9K/";
       spf=pass (google.com: domain of 3x5qhxwukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3X5qhXwUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p17si1540892oot.0.2020.11.03.09.58.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:58:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3x5qhxwukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id o135so18680855ybc.16
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:58:55 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a25:d288:: with SMTP id j130mr30666909ybg.378.1604426335148;
 Tue, 03 Nov 2020 09:58:55 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:32 +0100
Message-Id: <20201103175841.3495947-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 0/9] KFENCE: A low-overhead sampling-based memory safety
 error detector
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="MPs5H9K/";       spf=pass
 (google.com: domain of 3x5qhxwukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3X5qhXwUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

[ From v7 we think this series is ready to be included in the mm tree.
  Where appropriate, we would welcome additional Acks / Reviews by MM,
  x86, and arm64 maintainers. Thank you! ]

This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
low-overhead sampling-based memory safety error detector of heap
use-after-free, invalid-free, and out-of-bounds access errors.  This
series enables KFENCE for the x86 and arm64 architectures, and adds
KFENCE hooks to the SLAB and SLUB allocators.

KFENCE is designed to be enabled in production kernels, and has near
zero performance overhead. Compared to KASAN, KFENCE trades performance
for precision. The main motivation behind KFENCE's design, is that with
enough total uptime KFENCE will detect bugs in code paths not typically
exercised by non-production test workloads. One way to quickly achieve a
large enough total uptime is when the tool is deployed across a large
fleet of machines.

KFENCE objects each reside on a dedicated page, at either the left or
right page boundaries. The pages to the left and right of the object
page are "guard pages", whose attributes are changed to a protected
state, and cause page faults on any attempted access to them. Such page
faults are then intercepted by KFENCE, which handles the fault
gracefully by reporting a memory access error.

Guarded allocations are set up based on a sample interval (can be set
via kfence.sample_interval). After expiration of the sample interval,
the next allocation through the main allocator (SLAB or SLUB) returns a
guarded allocation from the KFENCE object pool. At this point, the timer
is reset, and the next allocation is set up after the expiration of the
interval.

To enable/disable a KFENCE allocation through the main allocator's
fast-path without overhead, KFENCE relies on static branches via the
static keys infrastructure. The static branch is toggled to redirect the
allocation to KFENCE.

The KFENCE memory pool is of fixed size, and if the pool is exhausted no
further KFENCE allocations occur. The default config is conservative
with only 255 objects, resulting in a pool size of 2 MiB (with 4 KiB
pages).

We have verified by running synthetic benchmarks (sysbench I/O,
hackbench) and production server-workload benchmarks that a kernel with
KFENCE (using sample intervals 100-500ms) is performance-neutral
compared to a non-KFENCE baseline kernel.

KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
properties. The name "KFENCE" is a homage to the Electric Fence Malloc
Debugger [2].

For more details, see Documentation/dev-tools/kfence.rst added in the
series -- also viewable here:

	https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst

[1] http://llvm.org/docs/GwpAsan.html
[2] https://linux.die.net/man/3/efence

v7:
* Clean up print_diff_canary() boundary calculation.
* Cleaner CONFIG_KFENCE_STRESS_TEST_FAULTS, using "if EXPERT".
* Make __kfence_free() part of the public API.
* Only not-present faults should be handled by KFENCE.
* Remove arm64 dependency on 4K page size.
* Move kmemleak_free_recursive() before kfence_free() in SLAB.
* Revert unused orig_size in SLUB.
* For KASAN compatibility, also skip kasan_poison_*().
* Various smaller fixes (see details in patches).

v6: https://lkml.kernel.org/r/20201029131649.182037-1-elver@google.com
* Record allocation and free task pids, and show them in reports. This
  information helps more easily identify e.g. racy use-after-frees.

v5: https://lkml.kernel.org/r/20201027141606.426816-1-elver@google.com
* Lots of smaller fixes (see details in patches).
* Optimize is_kfence_address() by using better in-range check.
* Removal of HAVE_ARCH_KFENCE_STATIC_POOL and static pool
  support in favor of memblock_alloc'd pool only, as it avoids all
  issues with virt_to translations. With the new optimizations to
  is_kfence_address(), we measure no noticeable performance impact.
* Taint with TAINT_BAD_PAGE, to distinguish memory errors from regular
  warnings (also used by SL*B/KASAN/etc. for memory errors).
* Rework sample_interval parameter dynamic setting semantics.
* Rework kfence_shutdown_cache().
* Fix obj_to_index+objs_per_slab_page, which among other things is
  required when using memcg accounted allocations.
* Rebase to 5.10-rc1.

v4: https://lkml.kernel.org/r/20200929133814.2834621-1-elver@google.com
* MAINTAINERS: Split out from first patch.
* Make static memory pool's attrs entirely arch-dependent.
* Fix report generation if __slab_free tail-called.
* Clarify RCU test comment [reported by Paul E. McKenney].

v3: https://lkml.kernel.org/r/20200921132611.1700350-1-elver@google.com
* Rewrite SLAB/SLUB patch descriptions to clarify need for 'orig_size'.
* Various smaller fixes (see details in patches).

v2: https://lkml.kernel.org/r/20200915132046.3332537-1-elver@google.com
* Various comment/documentation changes (see details in patches).
* Various smaller fixes (see details in patches).
* Change all reports to reference the kfence object, "kfence-#nn".
* Skip allocation/free internals stack trace.
* Rework KMEMLEAK compatibility patch.

RFC/v1: https://lkml.kernel.org/r/20200907134055.2878499-1-elver@google.com

Alexander Potapenko (5):
  mm: add Kernel Electric-Fence infrastructure
  x86, kfence: enable KFENCE for x86
  mm, kfence: insert KFENCE hooks for SLAB
  mm, kfence: insert KFENCE hooks for SLUB
  kfence, kasan: make KFENCE compatible with KASAN

Marco Elver (4):
  arm64, kfence: enable KFENCE for ARM64
  kfence, Documentation: add KFENCE documentation
  kfence: add test suite
  MAINTAINERS: add entry for KFENCE

 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 297 +++++++++++
 MAINTAINERS                        |  12 +
 arch/arm64/Kconfig                 |   1 +
 arch/arm64/include/asm/kfence.h    |  19 +
 arch/arm64/mm/fault.c              |   4 +
 arch/arm64/mm/mmu.c                |   7 +-
 arch/x86/Kconfig                   |   1 +
 arch/x86/include/asm/kfence.h      |  65 +++
 arch/x86/mm/fault.c                |   5 +
 include/linux/kfence.h             | 201 +++++++
 include/linux/slab_def.h           |   3 +
 include/linux/slub_def.h           |   3 +
 init/main.c                        |   3 +
 lib/Kconfig.debug                  |   1 +
 lib/Kconfig.kfence                 |  72 +++
 mm/Makefile                        |   1 +
 mm/kasan/common.c                  |  19 +
 mm/kasan/generic.c                 |   3 +-
 mm/kfence/Makefile                 |   6 +
 mm/kfence/core.c                   | 826 +++++++++++++++++++++++++++++
 mm/kfence/kfence.h                 | 107 ++++
 mm/kfence/kfence_test.c            | 823 ++++++++++++++++++++++++++++
 mm/kfence/report.c                 | 235 ++++++++
 mm/slab.c                          |  38 +-
 mm/slab_common.c                   |   5 +-
 mm/slub.c                          |  60 ++-
 27 files changed, 2792 insertions(+), 26 deletions(-)
 create mode 100644 Documentation/dev-tools/kfence.rst
 create mode 100644 arch/arm64/include/asm/kfence.h
 create mode 100644 arch/x86/include/asm/kfence.h
 create mode 100644 include/linux/kfence.h
 create mode 100644 lib/Kconfig.kfence
 create mode 100644 mm/kfence/Makefile
 create mode 100644 mm/kfence/core.c
 create mode 100644 mm/kfence/kfence.h
 create mode 100644 mm/kfence/kfence_test.c
 create mode 100644 mm/kfence/report.c

-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-1-elver%40google.com.
