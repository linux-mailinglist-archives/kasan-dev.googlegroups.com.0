Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4B5P6AKGQE35235HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 76E8229EC96
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:00 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id x5sf1755527qkn.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977419; cv=pass;
        d=google.com; s=arc-20160816;
        b=n+zXYH8GBq7GUBu1HDBOzChmDTMZQfYCUjheyVadyvEUTw+yyKDrQ8lwMYF/+z0Hyp
         SSgoR5OmEmTnCZD8auJTsov9rOX46O+MHyH4xh1zAOtz0Mjz29qIZUEclnNhJJuqaygC
         2oWM70dFC3AnvSfzfVeLrSKB5ThmFhDHqd3bFwVZYmcDUed2z3wv8VawRTiSfjRAEAfl
         TW3RQCKDzge3ktLA/MEZ84UH6gujuxrhHi+LAXMaHiEgINFw99e4iFP+DlKtH7dPWTl8
         Z0kBKogW6L1g4Pzjr8vgVIRbOy149hZjhH9grzcMAQKuvXIdGkzi6RYvUihP+P6aq1VL
         xwTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Z7Rkf+dlnfm2ckOmjLuZ4Gb2nvQpX/iWRwkvi33dOME=;
        b=Wy3oIT9rA848M11AkjT1bnVdbzjvUTL7znHrUcbuJqgsAoOq6jnt2+ioWHKJIXKXNK
         1vPNL5Pm3lj5rVMsuSQM3EZBAxa6Y3GDLYj3kebBkqzqm2r/x0oZhPtIUkHhVvibUkVd
         2M/xzrA+W5hUkltioUPlVEi/JVFBUe4OzK8A8ul050LKHobI5MvuSJ385QfDv4QM1BnT
         eqfIqzhfw7xujQ1Qk9DfiGUT1AF91apisRsMlX/uLZsAc81a8YG3HqQ/0HDahJmkj8nu
         Xy0br7JroB+dW7v/vQDIhxPYtDzOSk6cJpnUOEW944ivNNsw+sjOPg1K5NMPRXJX3L/c
         0gzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bkpQw3q1;
       spf=pass (google.com: domain of 3yscaxwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ysCaXwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z7Rkf+dlnfm2ckOmjLuZ4Gb2nvQpX/iWRwkvi33dOME=;
        b=VaABoGYiT3rPKjZN9DAj0j2+TNZdvX2V74bCSi0QHaxGEIfGH2/k59zk90HT9QUmYn
         eZ0X+oeCyuJATbsL8nCOOu8Xi8ftf49b3aVxEmJ7lC35ehkWomUT48mHtTMxr+LKPuXi
         j+VzHGYRlQFC56Tgal2ruqtN73Le6Vg/hWF5uSEVzaAuLo5a+8Kwoo5B4aQkGxA9gzWb
         KXaAOLdqb0Ss8zO15S+rbkvp6RZ80UnswWtM/ikx7b8pl+5HaLBjvRp5DP68Dfj6b072
         MWMoFu1beXMl6r0+T6fkFvexP7Cc/lhG29+I6oajYV31+d12J+WHcv+cx7v+59wJrGmT
         m7IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z7Rkf+dlnfm2ckOmjLuZ4Gb2nvQpX/iWRwkvi33dOME=;
        b=hvLJusJ7amPhqazIxIOA3u+F25ju40o6exQjQjcN/UGJRx3933CyrqyTGl7giMMPEl
         3T/D+NuGXzwCAxCIOB1BCVJgtSZx7+GGufKwnCYqogMx25SvhLLjdI2REkx7gbWVao3H
         ry+klhQB/yZPrqo4A9gk2GeL3WWDDUPbroVTs4mxEKKXPLEJ+Zzn4cX/XDzGcJu2XR5+
         Du6iMLwHza6AUJdMnGnb+so9+EBZOisZElLHAhEnTNEK2/TsRDDV2DiCIj6bS09HmJvm
         FmIn3cnDBU3CKHiqX005J87YfiIWsVHPBvCQpCQdbEooMUEjSHNzdiIJtbSVy64lXA0Q
         UbSg==
X-Gm-Message-State: AOAM531R/j0BPeg6Zun7BqjaN48smAsHxNXucHXg1vZa0fEUXHG1SGLA
	6/w7XPBIyU9DiGQ/WewAKBQ=
X-Google-Smtp-Source: ABdhPJyFE9jsy8YOSmip3DWBAsMGPDS0p4xFz237PAaZs8bppEDaFoXbYrMUNxSEW09B15Wqo4nkcQ==
X-Received: by 2002:ac8:ecb:: with SMTP id w11mr3466249qti.113.1603977419525;
        Thu, 29 Oct 2020 06:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1352:: with SMTP id c18ls1393353qkl.5.gmail; Thu,
 29 Oct 2020 06:16:59 -0700 (PDT)
X-Received: by 2002:a05:620a:16dc:: with SMTP id a28mr3687201qkn.372.1603977418939;
        Thu, 29 Oct 2020 06:16:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977418; cv=none;
        d=google.com; s=arc-20160816;
        b=ONVr6sL9P/QrYQ7v86gC2ykITNdEYg96MHu9FUHJ7A1V9E+ltxIEakGT/IJT57UCii
         Kl8dTjjhChWPcmoFrCwNALeTs9WGjWKMEr0dItMqmjc9/lCyyTDG3AP5ZEp1V+DupEGM
         Af6+rFTefJd5Gq0TvjgGwk3392/cvLRJKScwct0TDQoC7dJtNHhWkSpsl8LBFriYCONB
         cr93LgIuAcnVjK1WXfZn4UW8Q+LLo8+WwbkAcq6QuPaEpjOUXsmrtyXF1XnVH09/UaOv
         aeDwhIRg/gdek0AUKIDVBq0ZkbUL8WEVL2lx0ZM3D4utztYt4m+SjygngE+ISE7MMnfB
         CTxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=gJ+NyZrwSjh9xv4IitL3tDIsRKqkaN8A5XofNgnAjw0=;
        b=GnO6FZg9YX+DvKfqk18frwsu7dqvMD+0RBsQcX1mOh6dc0NLRnEF10eaCQ3wZxkGXD
         24UURT5m1jgonQNNbzkg7Pops3V1tkQyW+1A1KLEkmqbaKqoTBmO/GpKGzjeFO9b6a2/
         FuK+m7+sTjS7fpsYKAAT8bSO6/V5CMURr1u/uNO8lzW4tIjMsEFa5jm0a61x6d3YCoWG
         xuH90sPL5SvdXVTcCS/q5OlnpjpzXsR84xbdGVbExC/7kuhYGW0i5vBejCCrvrwmxGcO
         ySHmg5d2TpYIuVLkOHNaead4jv+Rg3yt9EpzwzjpahYhOUN4gQw+hRPurDN7aHnOYD07
         Ds9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bkpQw3q1;
       spf=pass (google.com: domain of 3yscaxwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ysCaXwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p51si210947qtc.4.2020.10.29.06.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:16:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yscaxwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i15so1841243qti.7
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:16:58 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:45ca:: with SMTP id v10mr4429043qvt.48.1603977418489;
 Thu, 29 Oct 2020 06:16:58 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:40 +0100
Message-Id: <20201029131649.182037-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 0/9] KFENCE: A low-overhead sampling-based memory safety
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
 header.i=@google.com header.s=20161025 header.b=bkpQw3q1;       spf=pass
 (google.com: domain of 3yscaxwukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ysCaXwUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

v6:
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
  MAINTAINERS: Add entry for KFENCE

 Documentation/dev-tools/index.rst  |   1 +
 Documentation/dev-tools/kfence.rst | 291 ++++++++++
 MAINTAINERS                        |  11 +
 arch/arm64/Kconfig                 |   1 +
 arch/arm64/include/asm/kfence.h    |  19 +
 arch/arm64/mm/fault.c              |   4 +
 arch/arm64/mm/mmu.c                |   7 +-
 arch/x86/Kconfig                   |   1 +
 arch/x86/include/asm/kfence.h      |  65 +++
 arch/x86/mm/fault.c                |   4 +
 include/linux/kfence.h             | 191 +++++++
 include/linux/slab_def.h           |   3 +
 include/linux/slub_def.h           |   3 +
 init/main.c                        |   3 +
 lib/Kconfig.debug                  |   1 +
 lib/Kconfig.kfence                 |  73 +++
 mm/Makefile                        |   1 +
 mm/kasan/common.c                  |  15 +
 mm/kasan/generic.c                 |   3 +-
 mm/kfence/Makefile                 |   6 +
 mm/kfence/core.c                   | 821 ++++++++++++++++++++++++++++
 mm/kfence/kfence.h                 | 107 ++++
 mm/kfence/kfence_test.c            | 822 +++++++++++++++++++++++++++++
 mm/kfence/report.c                 | 235 +++++++++
 mm/slab.c                          |  37 +-
 mm/slab_common.c                   |   5 +-
 mm/slub.c                          |  72 ++-
 27 files changed, 2771 insertions(+), 31 deletions(-)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-1-elver%40google.com.
