Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPH7QL5QKGQE657UEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D8AF226A625
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:00 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 184sf1064546ljf.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176060; cv=pass;
        d=google.com; s=arc-20160816;
        b=pRbcYaseE4x8M1pkL7gBUyTigyFbJ2k8uJtLowXugSo+riu34lAGaKeKCRZg4UJMWA
         n0W6F7wcTKou6P7E4XBHtK3NJsg6Fqq0RHgDxB7GTZMrrl9EyZA5LXMe9cbOM399pghD
         MjdJCWqgXgt0a8EwzCrYPQLay1ov4qzhK8TVUHNh3I3D0EO2s2uR924rwbexwQqEIslt
         KfGeu4Iaq8wQwcSbsYXkDh4OmPzSrL4Oygnt0wWUYsUvKqHymb6ziuxq1SG5qaXsVKUy
         zUV1hQd7KQbH8+En4hjdrrJR1QU2L0gYuAeaazIqJoClBf1JOHwwQrG0mJqsDo7sYKvG
         IwmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=YVePcFhgIxiPUlVz9Vh7phlgfuOmxmhpFRM4r96bgFk=;
        b=t+SkbmD3aAM498LR5g/+i7CjSh/3QsMGP8sib1MzWZNX2AEnr+IJO8BR+lD5vqgCWp
         T7sFoZ1JhOrZ74UQmqr1J89rDoOocEfflgGhsUg0H0Eng6A2oGKi8xzQSOrQEWljUVnj
         e1aiRJTRX6UFT4wzgZBid5AF/7ISOYfxx9lHcAMQ3XHiRZ3Rks0/ZvJIYJJUdhXn013L
         hXROmr6c6UyQuTCpD/TVhoYmYNAwghRt8bw99LFUx9SauuUAa5mOhcvyvwNw4kgmEgOt
         l4DgqKBiN2mJkdnIZLlGKkhYQOJyiSdJmAHlbmqXPtZrmbKx2IDkFuZlSSl+C52SFbAH
         WPaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XpeZsX3Z;
       spf=pass (google.com: domain of 3ur9gxwukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ur9gXwUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YVePcFhgIxiPUlVz9Vh7phlgfuOmxmhpFRM4r96bgFk=;
        b=jdpurd4Res/tMFuVBuScdFzDkdOEYHmhBr/uDlo73u1JmaLdtK79qwh6SCNXTmmLXE
         AZprIFhwvmccKhkEPm46lVV4KOUchUmQXXJHNvetKuPfRSGQOgshELAEi0K4vGuUqdjA
         /zPlf+xy3KBf8E0Vx64Gd+ZnumRv4tRtEqaksjutIzlgb1UxOJr6Sc7s4z4hRw/tTcB8
         I0MO2tKGZWnPajHgAY83uIUedQgF67uSNGltCHCYQU9gGr5r8YOfbC039VIm3eJD4v/v
         ekXwjwrWRazOEOeQrbH5n/BoIBH3ll3wApidFtf2nyZ1Q2AtAcq2FcHSe6ev6lWbh/gX
         Ts6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YVePcFhgIxiPUlVz9Vh7phlgfuOmxmhpFRM4r96bgFk=;
        b=Cfx/VkPAm823jEOqA8J433tQi7fVOcRX0JAmGz1cZ+cF/X1if7sX2DD/SYuHR/Li4K
         qIeT/EBiK3lhQOaYEx6AWnlIFGwVv9PBYJ8M3MR7VLQAg7bDjImSPfPRfUlVl+5BdSwQ
         Nb2Aj439DLxASH1HEF5g6fP0TbgSmPn50jg1hlkAoVyXw7t5aXebw7QLyTg8JsWwzssM
         u4NL1vq7eQmSeVbKb1sq8V3A9iqzAKvUNkNtvk+HeRb6L1N1JLLdSzdPilHtZHJAgtM/
         cq6lE6wTuvgXYgSRaauKLBJkBTY7JyO8az/Eh1Kt6SnkH4wZJ/mC3yucE2vG9+5m8SJM
         ewCA==
X-Gm-Message-State: AOAM5329L5eDTCMzs4sOwZUqxppE37pvsntfO3fLA12P1B7xhF5RSQOl
	0PKjWMQ6V7h0Y9V3EgWSjlk=
X-Google-Smtp-Source: ABdhPJzkRkh5bqZo8rD/VyrXE2t5W6mfWHP2mEWzkncOZD2t4aKo1UEwVWPheRz4kSHFMVpguIGrWw==
X-Received: by 2002:a05:6512:419:: with SMTP id u25mr6651791lfk.81.1600176060288;
        Tue, 15 Sep 2020 06:21:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls1190316lfp.3.gmail; Tue, 15 Sep
 2020 06:20:59 -0700 (PDT)
X-Received: by 2002:ac2:5333:: with SMTP id f19mr7051048lfh.339.1600176058980;
        Tue, 15 Sep 2020 06:20:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176058; cv=none;
        d=google.com; s=arc-20160816;
        b=Wwx9oIZmblE3FEIzrRqiDY41kPs4v7qGcsefxODulXN7P6LKiZzD/rr+Gh5lbEB4nw
         kdsi6bU2RkqjW3Bv6JtzcLYM82xwmzGNiv/sYbFQA0Q+/uIMBa74QdcoAXmVBXFNFG2f
         HoBrmESRwRG7d80caZB9BW31lDtj72I1M0IshNteu5OebhD6y8ceQHGr+tVOiYvbdWO3
         yuunfZej4uOwGITFSmdhR5/ZqNi5C9qNf5a3J3gq7zYvbWtdSemm8KBYV6kJ/qHMmwp2
         dk2aZcbYFj+mfZ3Qa8RfZJSCrs9SuxO5GFMBUG238hH8EtC2dtKzelk1AgVieI8Qm/rN
         gwRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=3v1WW0rh2eoeOYf+0D4JaYfcibqs7KNHQLEBt1uRbAw=;
        b=u+rOQ68Yo1dcpL0AgvLx/5/KTUZSw5bqkOlCIclmWRdTZeM7XKmCKUyt57DWSb04Yg
         kffxnrpCuy2iKPBBJD80jWNtgQ/MJn3pdMO6sjo4dMTapVtLcf22DeIU/8BbrxcQhYVo
         njg+nLAUc1xLexRPL//2tVm1cTcpKakoqJl7zYkPGybX6fD+JKWtPiwoBHv+/IBZ25fL
         l0NVbPoCJr8nW/KpUzykGTZD3IQuIyjuJJoOOcMHjbHWZFlm0Jvol4mlwl9L2Tzy6t4y
         W6as28WgyncRq8mU5OlIEywH4gjDuUZJxonKsBgWRpupQIOrXhhtDCsVWXX3uBN/Ck6A
         o2GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XpeZsX3Z;
       spf=pass (google.com: domain of 3ur9gxwukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ur9gXwUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f12si528107lfs.1.2020.09.15.06.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:20:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ur9gxwukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id g6so1228653wrv.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:20:58 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:600c:2109:: with SMTP id
 u9mr4457620wml.147.1600176058180; Tue, 15 Sep 2020 06:20:58 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:36 +0200
Message-Id: <20200915132046.3332537-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 00/10] KFENCE: A low-overhead sampling-based memory safety
 error detector
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XpeZsX3Z;       spf=pass
 (google.com: domain of 3ur9gxwukcb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ur9gXwUKCb0hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

v2:
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

Marco Elver (4):
  arm64, kfence: enable KFENCE for ARM64
  kfence, lockdep: make KFENCE compatible with lockdep
  kfence, Documentation: add KFENCE documentation
  kfence: add test suite

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
 mm/kfence/kfence_test.c            | 777 +++++++++++++++++++++++++++++
 mm/kfence/report.c                 | 219 ++++++++
 mm/kmemleak.c                      |   6 +
 mm/slab.c                          |  46 +-
 mm/slab_common.c                   |   6 +-
 mm/slub.c                          |  72 ++-
 25 files changed, 2619 insertions(+), 32 deletions(-)
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-1-elver%40google.com.
