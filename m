Return-Path: <kasan-dev+bncBC7OBJGL2MHBBROX4D6AKGQEXOWLTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 71F9829B01B
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:38 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id y15sf1187360ilp.19
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808197; cv=pass;
        d=google.com; s=arc-20160816;
        b=iF1AGgsiCtXS7H/dPc/50+qHxTEmU/lURbX6pCo0aQ4jMmAyYdHfxI2m+4OjiAeFXF
         mo2iSw/U2Zkd8H3tgScCKBxx8Ni0L9AjSyIfxksfLqXC4qI6NeyQnAQnF2qNtdyaCQaD
         37EFrRjhYf6y93pHw8pOwapsbv5YjggYwi4v/UMTLNQu+N80QPKCtS750xTxwx7DlPTW
         uAefiZhSAcehS8CHN6+wdiJr+7CG154NQUzblxtLrVLox+jWIhtP94vt2vqlSOrOr5jN
         tVAc3oi6AmESbRwZExROhhWTEUH2sWRoeNcaKYggV9//0JMxwAdX49NZMKithPZ/mEKi
         E5kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ivu1vbW7QHWQmgQp8rqI7p7GlqRMcvCkHV4jSz0ZlTc=;
        b=wkkN3OiFLVyVD7xbAqG7Z2qc2/UlFJOIFicnXfE1KWIAO+FyHWXuv1tjF4UMh5pSOx
         4fs4YR83Zvxw76emNgNTHToVQAV61YqXIFOsjgXhiw/C0gfKUxGuD+pwD9Cwdg3RrgrT
         4jiS12Q4K43wOgDFagV2aX7uDytUxbxPlA2bXfxVYKuKPJaSSi4twmg2nZRV6EM6Y3lf
         99qFunWSmvKSIB0rk5bfYmaglVaR9+esXsJol0YXdHxfkmi8RGO35fGywa1RU0V55We4
         l/WBSJVNvhq2m4cid45yGlWjZxm4AYhrXbORO9g6kS+P1egBoexZ3rn1KleNtvArec/d
         CSyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=swqC9CC5;
       spf=pass (google.com: domain of 3xcuyxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3xCuYXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ivu1vbW7QHWQmgQp8rqI7p7GlqRMcvCkHV4jSz0ZlTc=;
        b=aG3aShdafif/Tbn51DYgc1Vp108eN70XK+IXc6SKxTfkENMklRUmobUXqocDPwP9DQ
         iJJfEmxw+upOA8shla8bBHKt00miwpA0vadAg3NXPsNSu/OjdAHeZMU0sUGjh3lqEIuM
         LYwiYmEqf085aQJmGhZAJFVBiawn/rgi3qCQDYjJ3sDffFtPTzcV2frWVqkEpPMdkTl1
         /BJhn6n5o1/zvnaLVqWbfv861zR96NHVldDCdBIcDJDIga/XL0XUlMHcrpbx4KeZRX3U
         cjLBP6HhrAuKwkUsZz5qA+vXe7FzXaIkMeb2zzemcqKbSrh46TaZtOeQS3m+pOrvnfP+
         ikoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ivu1vbW7QHWQmgQp8rqI7p7GlqRMcvCkHV4jSz0ZlTc=;
        b=KhZLJXdSMbLnw1FgqPYbkia3H/JPOshY14QwfLOPN8L7FN78dgltpVDgxEIbDs3kVS
         dsDZDsO9ff0xAKprJJFr+wCHCTDHW936q/y1WHOKpESxax6q6M8UKy+RaQY2+0/w8nkk
         GeBTBr90BeqxltpBSTKpbEvyXArHVstIr+KZRyYRYu5whdpM8O+2iD+XDY/jDM9cz1YE
         iAnXvmSNG8BXWuAUeDZ67THD8dg5jM4xpxRNY05/pkpkMcQsvqJTtQOJWeUKOdiUgjmE
         wsENMZAKbV5ZwQB57vomoEEPzCBcyUzQ2EwrUlnU9Ae7ecSl4fYQgO2UaF5Fi1Bg9GhK
         8ghQ==
X-Gm-Message-State: AOAM532gfCMnWG9mJmXtxCruuS2cOFItASH+FEjSSkyjuGXOzqSszbXS
	BLdJnNl6OeQmC4Mci57KkiY=
X-Google-Smtp-Source: ABdhPJwlS2P3ZGnYDDS9WvS2vsJFtFa9eSY9mrPqQap4QNyHfspI724sRO4s17+UO29O03455ZmKcQ==
X-Received: by 2002:a05:6e02:541:: with SMTP id i1mr1822159ils.156.1603808197180;
        Tue, 27 Oct 2020 07:16:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9a87:: with SMTP id c7ls254707iom.6.gmail; Tue, 27 Oct
 2020 07:16:36 -0700 (PDT)
X-Received: by 2002:a5e:961a:: with SMTP id a26mr2225318ioq.48.1603808196795;
        Tue, 27 Oct 2020 07:16:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808196; cv=none;
        d=google.com; s=arc-20160816;
        b=vW+TaFgCS8dFPTg2Feu881DyYlHeiFFz2PzxDL1LoSxug4GfD42S92EjwET+MToSEg
         oxec69kivvqwYb5eTG5/+mmTXIIiwacOI99vJnJNp3BpxDn+LCva2ozzDKAjRPqmVsMn
         to56h/KSq6gp3jluetvQTFIN9smfUgi/2kMK7XQA6zYFEVLRJ6kvg7ae2H+aepl7vDHl
         m+MgcYL565jDwLji+Qtvw+gB6vyTIFHljijikRuuMqIAfjd44Eq6gRDvGl6VIHc3HpOY
         lscWCry+MF3r7T88yn/bZbaxj+1jadoTFVEwovfeMNe23lXWj9W2cZ0BT5aG4mSmcCKl
         68sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=OIhtJmQn8cPhTYAMUsg4K5Bpc/At3M+CZmjJH0wJYj0=;
        b=H5pfF7l+mKSMNiz3MkfCKT3AZYSHouI5m4wi9dtujYCMGIgFiuFl//KblayqbcEEMt
         hf4sYUTsqwU0Q5MO2pygzW1J3Ir8GK0twrJO33sZiK7x6YAQ3WTh5KsyW74U6Ya7gzBs
         TQLvxWsitnGpXP+894WFYmRDqwdEprZPLFxYZ5Wz7v8KxITsHS21T/YUU/zQO089SlEW
         WCz8jMvgAbFH6CxgHmBWq1bk4ifQDglgqey5A0g6t/LsE+nQxdoHwKZ8KVYu5d5AkOKl
         57FqoFFEPZ/nlr2RZyBULPxyxRMpAwtfE6oKSj4WXD1pF+cyCpwKvOm5/nkbyNwJyv1Z
         yu2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=swqC9CC5;
       spf=pass (google.com: domain of 3xcuyxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3xCuYXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id p5si103413ilg.3.2020.10.27.07.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xcuyxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v4so876197qvr.19
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:36 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:fa91:: with SMTP id o17mr2582669qvn.49.1603808196014;
 Tue, 27 Oct 2020 07:16:36 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:15:57 +0100
Message-Id: <20201027141606.426816-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 0/9] KFENCE: A low-overhead sampling-based memory safety
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
 header.i=@google.com header.s=20161025 header.b=swqC9CC5;       spf=pass
 (google.com: domain of 3xcuyxwukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3xCuYXwUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

v5:
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
 mm/kfence/core.c                   | 823 +++++++++++++++++++++++++++++
 mm/kfence/kfence.h                 | 102 ++++
 mm/kfence/kfence_test.c            | 822 ++++++++++++++++++++++++++++
 mm/kfence/report.c                 | 236 +++++++++
 mm/slab.c                          |  37 +-
 mm/slab_common.c                   |   5 +-
 mm/slub.c                          |  72 ++-
 27 files changed, 2769 insertions(+), 31 deletions(-)
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
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-1-elver%40google.com.
