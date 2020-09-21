Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDOUUL5QKGQER7FTKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D2BD527255A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:37 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id d9sf5865212wrv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694797; cv=pass;
        d=google.com; s=arc-20160816;
        b=kEdrY8Eac9VjlFQCW4OWLQdMws2CHvHg153eE8xr/pUI+Ba5UsHj2NilfKmLmDuKGF
         X7HRlPb0ZuN7eH4q/cKPg4ko7CIaMbLf3L0URx9qjmV58G+CmYm5KjS3oE1Njo+X/anB
         9DeTVat8/56MwgxtINFgYCj5ZoVLUH6BffBytEEIGsleIL5y8sVrXFrdzSD/SDMvTGeG
         ZSBleWLJr15PZqqkaE5tFglRozBzp2qqRGNC0rh4I/Cx1R9aBd9H+1uWaqYNNdW4nSCc
         3b3dCRGoZIrluVVqEFUNF1JG1LAcNs2ZYErAKPqfNqGMzl9gV+ool2fTbkxHlfssRLRV
         O1ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Kk7EmcdrREpVN0IR7KUFLX//CzVdnWpl2gFtq8Bwu4E=;
        b=pvKA6+F/oVg5dtka5HgC8LyLJEeUiYzk2xtWX8s37wDV/3h0LmetS4X84Buv5m8dxM
         FngpiFGJzdoTWZ9UL1szq4fkBeXR72f4Ygg5TRNB8WLRwJcWoqa7rnHChePmcCIJ1EBr
         vkNvA8DDxyINxTa0x85faVtcvgzDmARW/+oq+gL7oYtMZ9zCoaZtTG4qE8oKZPu0v47A
         9HUOZ49qRpqy3Ydy1YViH9oVrFDhjsLX2Pr++l7j3rTGS+y9CC0tSXrgB+hyWoNpIvsg
         U48uHFjsEmV5hXERYiTBDqALhgt5yMRJYSNBBs1qiwg6e7p5dr4avCQsl7/PxQsjVQ0u
         exsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lnXG6wiq;
       spf=pass (google.com: domain of 3dkpoxwukcqujq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DKpoXwUKCQUjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kk7EmcdrREpVN0IR7KUFLX//CzVdnWpl2gFtq8Bwu4E=;
        b=fTNFNErCBOcfZyrcCIvZKy/XSMiXlV29+4zrgNhBwmg/AySPSp7CfGU8K1uKzVfXe0
         4wQSSWp0tqMBM0wGk3lCnE20ch5mxI8v0OWt+Kcs7Q375mM9Bre0HAXXy0SbqLzboYdG
         rZCA5LnQtMhckbnYXkamCh9YJNf4J0NZu2aQQKonYP1xvtsKm2UugnbpVIjANRphYS0g
         rZPTOfTQ2xNBweqtL5Br3r4XSMfZNoyssrVDLn9lUzo6Hgetto1/Lv6QnVFilcBBjYyL
         uBfZ9hKLzlKC/ddLn6O5NGz1+55QjJKrUVBa1CgGLEwvZce+31hI4ZD+2qIb1bLHcQhL
         /BHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kk7EmcdrREpVN0IR7KUFLX//CzVdnWpl2gFtq8Bwu4E=;
        b=HfHJlKKG0XESlGLFJVR8JAZITPlhE1JILKDJSA/Awxh7yX2osW51kiqCNZmjHImMxt
         8w+iSR0AKW3tfixtNa2nz+cIhk61Euzw0uyAfOi4scFBhXrrO59ikDze482eC1QQ+rN0
         QGAq311NZiEDrAw2s5PDuVjK0aHJOWeT+yCNdSy89BeVQdXSqflis2bh6x68+sg1Kqin
         uxelFuRJtUKk2wWug78TBPB6PxmNrqVyyJfE8tWhhgaB5lTOUvg56L7G8PvWbDaOpcIx
         KBp6WEjnf8gHMvxM1IBU8CFaCgnBv9zaAUVsco2/d/B+FktqRbkkek43KyW5LcmLGCTc
         3lHA==
X-Gm-Message-State: AOAM531yg0VjpK9taKyc0jy4806NV+5Ehn70l/8hO+fl0GIInPBRY2Ro
	2qCvf1UeGaUkd8tnDA3IOkA=
X-Google-Smtp-Source: ABdhPJzrjTV61CDE4qlnE4Wm5B11N5j+qfrMdbsxM4FnxbsBimOCJe4p6oNYSjadjFZ+lBmg9UkErQ==
X-Received: by 2002:a1c:bad5:: with SMTP id k204mr31277809wmf.111.1600694797604;
        Mon, 21 Sep 2020 06:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls1633234wrx.3.gmail; Mon, 21
 Sep 2020 06:26:36 -0700 (PDT)
X-Received: by 2002:adf:a49d:: with SMTP id g29mr31846627wrb.219.1600694796638;
        Mon, 21 Sep 2020 06:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694796; cv=none;
        d=google.com; s=arc-20160816;
        b=nLReiaCZJyVqggPTwmLNlrSiJodh5jpoerVVPmz+hWEVWk1fWzdjVao27+W6hDVgdN
         EGx172QqttkUb+Ah4K0h5tFggu9g4F8xTYEjwRkJIeOis5LPP6UcfPkDuysV52mc5PzF
         4j7lUiOAJiqiexVshHWWmnAcr/aH1xcmBaFww6DMer9iGQCFg+4TSXTKt1yyouAoVoGg
         vnEClsP9GgeswfH7bfMiJHB3NqUWE1xhdOYFYgwwpt9QEU8QCEcQGR5Vn3zdvJfw71HL
         yrqGiEjsd9Di8wVCmlglnlOp9d9YoPYW7FQ1RTn45/2mZHKPBNWRbCRX7jzz0hbewG4K
         lwZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=EdTmVWGaBxdasegvEqn7J8/FntcyBLgQW6ssuU6G+uY=;
        b=NpP6d0+FgU4S0qgT9ZNCFqlgpur5DvgsDYAFdSCmyfZ6xpK0wVqIBaDd9FlTKtHsSR
         LLlieMfy1UcKDjS7NJSaoZxA1yCMoj514ePB/UQai+Fkjb3M37zVbH/x8i3dDDNNX+Q3
         mrHr6PP0YnuRcSdZGfkamKA8P7VzMkcYlGzxyxwzQ9Fbmitqu1e17c3iBB8D3ig789/8
         Az0r3w9sP2FDaSpiWAwz68ddK6oUP2DtuHLfTKAnv4CLnIUkRRdO2YWpgTXK3uf24QKi
         zbNHJqDkQ2bCxyw1ma4J5IkLcypbMmICJdlZtY383GSC+2edep0uAh0izxgQmVInrjdM
         l/mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lnXG6wiq;
       spf=pass (google.com: domain of 3dkpoxwukcqujq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DKpoXwUKCQUjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v5si300362wrs.0.2020.09.21.06.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dkpoxwukcqujq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l9so5836557wrq.20
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:36 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c1d3:: with SMTP id a19mr29455454wmj.19.1600694796072;
 Mon, 21 Sep 2020 06:26:36 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:01 +0200
Message-Id: <20200921132611.1700350-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 00/10] KFENCE: A low-overhead sampling-based memory safety
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
 header.i=@google.com header.s=20161025 header.b=lnXG6wiq;       spf=pass
 (google.com: domain of 3dkpoxwukcqujq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3DKpoXwUKCQUjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

v3:
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-1-elver%40google.com.
