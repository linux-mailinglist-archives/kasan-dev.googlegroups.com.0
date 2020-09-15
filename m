Return-Path: <kasan-dev+bncBCMIZB7QWENRBB4NQP5QKGQEMKTCBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id E10D726A68C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:50:00 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id x191sf2918641qkb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:50:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600177799; cv=pass;
        d=google.com; s=arc-20160816;
        b=qXW+ePpzrqSRryi0OWQVjZIjB/lGL+m43G29I+Zd2fSs8C7h3Aafx9B3d42kh6qWlV
         yBTB31KehbN7/B36DO0TT2VTZu0QhrlZ/EXZVjlbl1ge3DkYEm44d0tKszQ09bgsJ6hn
         C05W1D7LTnFfmzJFmWM8dWbXN2hxdzi+dk3jerrtrt81RdDJvpoQaf/VzM0gBOvv0YW2
         5Z1IfbaZ6JcxpHPPmFzfBTb9cUd5FOgcuw9VyhRngiHkF6no37Lxv+/PhL5pAeDYYCf0
         39ZeGPzLbMYHNYKiZKUBf6BXKhS2tR1lnT7wRIRcSzFsK8dusP19vrT4qXorbgjkHCAw
         oOug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z+x+qCsF9CcW/wbbdt+TbPgM6FKRvLpVVv+Bb3dyElI=;
        b=NDoxuUmuTqgEnXh/Vzo5mZ8xAOqs7UHWC6HeZvQ+U2GUA/rvggwYQYgUi9ATTj7dEn
         chyiz3iVZRsWAlh3JH7mHAs2Rok5x9zADqQdCVNebfzAV7NzvBgCAlajS8puj0AvQ7Xy
         EoF7NFM6rTWTTKnVAy5Dz4tzzSmXeofLS3SPHc5ptGc09a7eXk4paJ57WkKSPUqrYrqO
         fnClgvKJInvf8+hXXZApmZ12o1tzynLgvOMlMgepURkOSK36U1GKcDmEu4EhWwZfV0bH
         jCmgvFfGN3RY0npdfpX2zHCPcWNHeXyHdNqRFfwUPbpZ0rYxftLEW6hVjKMOOpTEY0nZ
         d7Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="h/IVba/6";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+x+qCsF9CcW/wbbdt+TbPgM6FKRvLpVVv+Bb3dyElI=;
        b=qTlie8nnaOatv7xnWHcHIi177Qv1Fj7i3K3F69NAfnTld0ClfkiDjufN5Isacs962v
         42oxvLrWortoA1ctLz0AA3VZvC5iDcVAOwXx1/mLu2jWCSCOaNcnKfhFXhOSvcQsgxwM
         WRrVS+NMJ/4CJqpKZx5I4Ae25870tHryIUFc6pZS/GoRsd15EnfnMXc9GBdjv2ZFISvD
         TtsV0N1CcithGlmltErwv3K7cOW1OlzeJ2QNla4XouDGIyflJFEwW8kstGOMvQtQd/PQ
         0/LBFvVnrHELBK0m/E2njKPsCKoviy1B1GEFwj/2o2zAs4lp7ieYAaBNVDt2dItmpZt+
         c0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+x+qCsF9CcW/wbbdt+TbPgM6FKRvLpVVv+Bb3dyElI=;
        b=r2mD7+pxfuo337mu4CHY8d61Zxl0l4LUFlG2QAzk+Cx3soedkz8MuGhe5L/xqh8Y3e
         yiv5vHDRt4WQNKD1XQ08lGY8XgWlt/cIDowfi7/7CyFizWpMDLhHSc71apiU5e01wdvY
         2fOuX/Fj0aJ+duw9tIVSuTD1s0Ev82571pe5IwGGKLUOdTTdJD64ffqp9SkD2raIP69S
         JpJ8P3qMo0y3hkm+2An5pSYb9nMRX+yh5jp2UxnRyb8esctMqE3yIk2sxc946PLxd4kE
         gUw9P+NcD232idhrGTigxFld385ul2VRheK8dqf8tr5iWN4uwPtfHriyRs6P58p4oYuH
         KvRg==
X-Gm-Message-State: AOAM532+SRpFW0Pf4hEJKohhUEzG+hCK3GchTpN88NtfgdoUTtTqtQwj
	lThuP1C8CCdT0UfbEYH7KFc=
X-Google-Smtp-Source: ABdhPJwLtKezRqY9V1gmacbG/bbiwW1pIC0JqdyG22H0FgI3gFrMXOTMEIpO72L2K69VV2aSLjYz+w==
X-Received: by 2002:a05:620a:15ac:: with SMTP id f12mr17252637qkk.19.1600177799635;
        Tue, 15 Sep 2020 06:49:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:136e:: with SMTP id c14ls1398816qvw.10.gmail; Tue,
 15 Sep 2020 06:49:59 -0700 (PDT)
X-Received: by 2002:a0c:9e0e:: with SMTP id p14mr1822648qve.25.1600177799231;
        Tue, 15 Sep 2020 06:49:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600177799; cv=none;
        d=google.com; s=arc-20160816;
        b=u8YtZGRhKTi2qwH2dPD4YQ2mWbrQbedxw17CTI0fSXVXwOINWj3Ii9TXju41zev9BZ
         Hozed3+nQVRmh86w3j8Cmp3Qxlu9MpLXbRCM2L6FrqN6STK8zc2V7z2jarmuX0uq5r0c
         TB65CxLRJ9+Bj5B2bvv4HvSYamoqRrpPa5blqIwWdmuVwUXMqMxhQKHhNXi4eMyh//Ue
         uHSwkKczyM0CJS/gm6jymf8V/8oyLTPcM4fQLa0UYx9tE3TBqbQ8MCNtLvFTXthfB6rB
         ZsxnriAv15QZl2OZij3pSIixSSE/XLi8Ch+C62mNurbHSQJrliZ8+zeCGmN11ky2UxKp
         LoxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WtBJz+0p08+L8y6UxJF+d5EvYqNw22qJSy8aseGAB8M=;
        b=OBrs99Mv21Bvo7yQN6GGr98hPUgnxEmRnj7/KBvGyUauHc3yNxVO5fn0bTxddRlBwr
         0w0T26bmrxpfO7uzb3esj36IO6/T1LBn8UbevKs7XF2qm2giosbn5tCOkmalb5eHFZZK
         Q3Z5zSnC4H8a87sdY9fFhJn2dbrnm8s3pqSht48G5yFdx0Iy6Z7LBS0A/rfiuNczNqbB
         /UNgyqIfrEmBOZPmcx+BRIS4vVXzibvm+9lumGp5MoRIWfivUDh212OJGX3EP4BIncG2
         Lpbzmph8yIVZ24KP5vcC2qSmkjUIVlAJS4fubH/U8dH8/Ma5jSDkx4wD48Mz9yVfaemn
         87bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="h/IVba/6";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id a2si793373qkl.4.2020.09.15.06.49.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:49:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id t20so3166968qtr.8
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:49:59 -0700 (PDT)
X-Received: by 2002:ac8:4658:: with SMTP id f24mr18082864qto.158.1600177798597;
 Tue, 15 Sep 2020 06:49:58 -0700 (PDT)
MIME-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Sep 2020 15:49:47 +0200
Message-ID: <CACT4Y+Ywx8G9W8izyiDAg1usHouSLds7E3XU0WJctCucDku_eQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="h/IVba/6";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Sep 15, 2020 at 3:20 PM Marco Elver <elver@google.com> wrote:
>
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.
>
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
>
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error.
>
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval,
> the next allocation through the main allocator (SLAB or SLUB) returns a
> guarded allocation from the KFENCE object pool. At this point, the timer
> is reset, and the next allocation is set up after the expiration of the
> interval.
>
> To enable/disable a KFENCE allocation through the main allocator's
> fast-path without overhead, KFENCE relies on static branches via the
> static keys infrastructure. The static branch is toggled to redirect the
> allocation to KFENCE.
>
> The KFENCE memory pool is of fixed size, and if the pool is exhausted no
> further KFENCE allocations occur. The default config is conservative
> with only 255 objects, resulting in a pool size of 2 MiB (with 4 KiB
> pages).
>
> We have verified by running synthetic benchmarks (sysbench I/O,
> hackbench) that a kernel with KFENCE is performance-neutral compared to
> a non-KFENCE baseline kernel.
>
> KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
> properties. The name "KFENCE" is a homage to the Electric Fence Malloc
> Debugger [2].
>
> For more details, see Documentation/dev-tools/kfence.rst added in the
> series -- also viewable here:
>
>         https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst
>
> [1] http://llvm.org/docs/GwpAsan.html
> [2] https://linux.die.net/man/3/efence

I see all of my comments from v1 are resolved. So this is:

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

for the series.

> v2:
> * Various comment/documentation changes (see details in patches).
> * Various smaller fixes (see details in patches).
> * Change all reports to reference the kfence object, "kfence-#nn".
> * Skip allocation/free internals stack trace.
> * Rework KMEMLEAK compatibility patch.
>
> RFC/v1: https://lkml.kernel.org/r/20200907134055.2878499-1-elver@google.com
>
> Alexander Potapenko (6):
>   mm: add Kernel Electric-Fence infrastructure
>   x86, kfence: enable KFENCE for x86
>   mm, kfence: insert KFENCE hooks for SLAB
>   mm, kfence: insert KFENCE hooks for SLUB
>   kfence, kasan: make KFENCE compatible with KASAN
>   kfence, kmemleak: make KFENCE compatible with KMEMLEAK
>
> Marco Elver (4):
>   arm64, kfence: enable KFENCE for ARM64
>   kfence, lockdep: make KFENCE compatible with lockdep
>   kfence, Documentation: add KFENCE documentation
>   kfence: add test suite
>
>  Documentation/dev-tools/index.rst  |   1 +
>  Documentation/dev-tools/kfence.rst | 291 +++++++++++
>  MAINTAINERS                        |  11 +
>  arch/arm64/Kconfig                 |   1 +
>  arch/arm64/include/asm/kfence.h    |  39 ++
>  arch/arm64/mm/fault.c              |   4 +
>  arch/x86/Kconfig                   |   2 +
>  arch/x86/include/asm/kfence.h      |  60 +++
>  arch/x86/mm/fault.c                |   4 +
>  include/linux/kfence.h             | 174 +++++++
>  init/main.c                        |   2 +
>  kernel/locking/lockdep.c           |   8 +
>  lib/Kconfig.debug                  |   1 +
>  lib/Kconfig.kfence                 |  78 +++
>  mm/Makefile                        |   1 +
>  mm/kasan/common.c                  |   7 +
>  mm/kfence/Makefile                 |   6 +
>  mm/kfence/core.c                   | 733 +++++++++++++++++++++++++++
>  mm/kfence/kfence.h                 | 102 ++++
>  mm/kfence/kfence_test.c            | 777 +++++++++++++++++++++++++++++
>  mm/kfence/report.c                 | 219 ++++++++
>  mm/kmemleak.c                      |   6 +
>  mm/slab.c                          |  46 +-
>  mm/slab_common.c                   |   6 +-
>  mm/slub.c                          |  72 ++-
>  25 files changed, 2619 insertions(+), 32 deletions(-)
>  create mode 100644 Documentation/dev-tools/kfence.rst
>  create mode 100644 arch/arm64/include/asm/kfence.h
>  create mode 100644 arch/x86/include/asm/kfence.h
>  create mode 100644 include/linux/kfence.h
>  create mode 100644 lib/Kconfig.kfence
>  create mode 100644 mm/kfence/Makefile
>  create mode 100644 mm/kfence/core.c
>  create mode 100644 mm/kfence/kfence.h
>  create mode 100644 mm/kfence/kfence_test.c
>  create mode 100644 mm/kfence/report.c
>
> --
> 2.28.0.618.gf4bc123cb7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYwx8G9W8izyiDAg1usHouSLds7E3XU0WJctCucDku_eQ%40mail.gmail.com.
