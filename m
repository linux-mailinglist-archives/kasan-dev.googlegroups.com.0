Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7RZT5QKGQETUFSN4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 932F127CF54
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:44 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id u5sf1203216ljl.16
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386724; cv=pass;
        d=google.com; s=arc-20160816;
        b=DLQ51sZUMTXZQKtK1dq3U5d5mjphbdzNSt6H7LcAnSo/z/8pIQkESNjebeH8BPCt9E
         B87MhIiaWXUw6leZcvcp6FrQMkU144F4yipgvVa52mOXIFv/8lrboF+Q1GQagIVvfiXD
         /Clzm9mCjntfitg0xfKOE39m9BMf9/4YtAYtdo8rR7kQ3iFTkzRa348mDBt6CaWSc/cP
         DpLxpWMgQ6kUH+oEYD/gVTQRWZrrAFKQsr1Jjwy6BHjIxxiic0V6AcqYW4h7ayVwT6+t
         3Km4TSR8V/GpMdQ0AmFNg8xdsacxYTp3cER2bPB2caV86LUrY+ssgByfr+dkkUWbJ6Ir
         5aMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Q2HOJQmbeLz6UATFsHGK2s6ESnAi1bsWzXCRhuSrFRU=;
        b=xohg402afDozt4DZ3O7nyV8JL/89EDtZ5e68cLZqbMTsERfzQiDhxBsiweI6r0i3kY
         wC7TnaPmQKuSMpVOznmwQSLJMSXkTNihW4uaCwdYR8dZKxeG27CEfwpfkE3FzUmH+1g0
         K2jPMhVJbOy7QPwYQVqdHsJ4GgdmlibQWRNmN2f/oVPiAFZ0NS8jTGL0ApmAh5/pz/zf
         Q4xy5rgZInw9O9MDqBlaKBPTePjmLDEVmMMT+b/gZGn7/2QRRWggY9VND/pF/rDQ/a5Z
         PBW1t0C+wZFX9xpl3voW8FQBFiHvf6tML3+J5jvxLza7819jC0bvXW3rhqXeoPbGYNjp
         zxrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YQlZfknS;
       spf=pass (google.com: domain of 34thzxwukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34ThzXwUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2HOJQmbeLz6UATFsHGK2s6ESnAi1bsWzXCRhuSrFRU=;
        b=WnTxsTmuGSAZKQfYeiY+bwK91Jbpu8eDTtEWgKOzjCZz3U5wNUSRR0GC4eUGYsqthx
         7E3fpLTEvU7pnyI+lHsSA1eXh51xkXS4tyMcU/RUf3mJL5+CHUWfVKn22zU3LlSAYkg0
         C+diQP5n9P9++Y4rKmJZBu6rICbGgYSvc7xekOtgKOePGJbJxrAp8W0sJKgTXQIt2xYI
         L4CO7lq6sjX5Uuk+83sznyCIcKHPubx8RyNU5enIt8QepMeBVUDuO0tzJBpyDpj/pa+r
         ftty0Pi9tjsHXY44cB4pwYExMr1yj3rD3G3mmNMCsMwlNPZY9scpNYHz6SXeP4iuDsk+
         yftg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q2HOJQmbeLz6UATFsHGK2s6ESnAi1bsWzXCRhuSrFRU=;
        b=k7xoN9FVN+L+CTHkqBvOPS4ltLEfWnuSPnjHpsEjaRZD4MzXWqIRZX0Dw+MsrB7rYM
         AWwsT5nGT7v/gotwzVXc+tK0DJG59T+tOTad+r7SCrkcv9Y9x/+VS1+pTkWo2kj0tcgy
         vZ3kziI36Z92N2kSkY230xx/RgQ63dOXvCoe9G8O0Y5RDTygsOVfUMJrU+xSjdqEcBLU
         LFOwHIgp/i3YPidZGbWJmTDly8oz5FVHfZeWGU0o7PCLQwdhAJ6QnmOkhkeUHPxYUSSg
         1QlwXjQwPgK0mwgqCdIllCvh4IA7d+reZmAUw2a4dhxNTZ/gbbcXG5FDJPsHeD5liKGw
         8E+w==
X-Gm-Message-State: AOAM5336WdItkFtd85L2t4i7LxA911FWdVcSGQLioNPppEYHIoUWetHs
	/HgBiLKoyjrqISpZ7qcRO6Q=
X-Google-Smtp-Source: ABdhPJxH1GpJ3DN0VaVbRvisDG5ujLTD/hTsL78tRJAGOW7fd3FpaTUxF/+RXnDainHQFdv7Q5f2Sw==
X-Received: by 2002:a05:6512:3f3:: with SMTP id n19mr1159801lfq.531.1601386724047;
        Tue, 29 Sep 2020 06:38:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9151:: with SMTP id q17ls171556ljg.8.gmail; Tue, 29 Sep
 2020 06:38:42 -0700 (PDT)
X-Received: by 2002:a2e:2e10:: with SMTP id u16mr1287927lju.40.1601386722833;
        Tue, 29 Sep 2020 06:38:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386722; cv=none;
        d=google.com; s=arc-20160816;
        b=zNEvL9muEvjxSN7qpHhbMY8nu1B6ACqxTzO75KrIEZIVXksZ/cSCeNHVj8vrDNuWO/
         temH99sFyTIiyNgYzAUGNozs4wr6wPWudjhEwOW3G8EDoZGqpwRoITSgyDVkYBYNeacQ
         jxw1qTw12Gii8PGAPUb2tvOOmt+SuFp7SrDJx8X1UWh4pY5OgBDw3pLxuumN/l59EzrO
         aAkpMIe18mjK909+BNb9NuuwEs749SGUoClkSnuzZY2JN86WhOkr5/nP8uL8t5Ivhkvg
         cUcRBJePavj3c5YJssSiYKKn3RWtRblRLU/4HU5eHOIG0Vw0S7e2k1JHm87zEd6nI5fs
         Lcpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=z1cXfrxOGzx7xyJIGn8IR6C4kJWaluaZ0MOMBbLzink=;
        b=FCgOUcpRP6h90ItJBxi0Jo58xjjJl7OkiocvGyfOVkAVCRacSGxCPBQj/UsEfSQXjJ
         20WAfFkoETFJRYgV7ZvISmg14oHJp3NgTBMHnsPchrn6VHaEhn4a90hf+Zb+Z0WVXqPi
         jNUyWfZe2Fqf8OuB3THxdqHFTt1pm2zC6J0fAaVj3tht7bI2oKKWEbks1etPPVEC7QV2
         UKQAqDyz8q8rQj4PnS2R6fKjCtyVPdvYPlChSpAISUF4+r9OkdJUIwbLxMH8/nslbSv8
         F+1LlDDiy9XR4/mReAW2719Cgm/el7nWKpQtpuhoEhARVvcpzneKufh/wD+FGgBsSwMm
         bUvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YQlZfknS;
       spf=pass (google.com: domain of 34thzxwukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34ThzXwUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id r16si241046ljg.1.2020.09.29.06.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34thzxwukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 23so1719846wmk.8
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:42 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:cd08:: with SMTP id f8mr4611202wmj.124.1601386721987;
 Tue, 29 Sep 2020 06:38:41 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:03 +0200
Message-Id: <20200929133814.2834621-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 00/11] KFENCE: A low-overhead sampling-based memory safety
 error detector
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YQlZfknS;       spf=pass
 (google.com: domain of 34thzxwukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34ThzXwUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
hackbench) that a kernel with KFENCE is performance-neutral compared to
a non-KFENCE baseline kernel.

KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
properties. The name "KFENCE" is a homage to the Electric Fence Malloc
Debugger [2].

For more details, see Documentation/dev-tools/kfence.rst added in the
series -- also viewable here:

	https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst

[1] http://llvm.org/docs/GwpAsan.html
[2] https://linux.die.net/man/3/efence

v4:
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

Alexander Potapenko (6):
  mm: add Kernel Electric-Fence infrastructure
  x86, kfence: enable KFENCE for x86
  mm, kfence: insert KFENCE hooks for SLAB
  mm, kfence: insert KFENCE hooks for SLUB
  kfence, kasan: make KFENCE compatible with KASAN
  kfence, kmemleak: make KFENCE compatible with KMEMLEAK

Marco Elver (5):
  arm64, kfence: enable KFENCE for ARM64
  kfence, lockdep: make KFENCE compatible with lockdep
  kfence, Documentation: add KFENCE documentation
  kfence: add test suite
  MAINTAINERS: Add entry for KFENCE

 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 291 +++++++++++
 MAINTAINERS                        |  11 +
 arch/arm64/Kconfig                 |   1 +
 arch/arm64/include/asm/kfence.h    |  39 ++
 arch/arm64/mm/fault.c              |   4 +
 arch/x86/Kconfig                   |   2 +
 arch/x86/include/asm/kfence.h      |  60 +++
 arch/x86/mm/fault.c                |   4 +
 include/linux/kfence.h             | 174 +++++++
 init/main.c                        |   2 +
 kernel/locking/lockdep.c           |   8 +
 lib/Kconfig.debug                  |   1 +
 lib/Kconfig.kfence                 |  78 +++
 mm/Makefile                        |   1 +
 mm/kasan/common.c                  |   7 +
 mm/kfence/Makefile                 |   6 +
 mm/kfence/core.c                   | 733 +++++++++++++++++++++++++++
 mm/kfence/kfence.h                 | 102 ++++
 mm/kfence/kfence_test.c            | 783 +++++++++++++++++++++++++++++
 mm/kfence/report.c                 | 225 +++++++++
 mm/kmemleak.c                      |   6 +
 mm/slab.c                          |  46 +-
 mm/slab_common.c                   |   6 +-
 mm/slub.c                          |  72 ++-
 25 files changed, 2631 insertions(+), 32 deletions(-)
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-1-elver%40google.com.
