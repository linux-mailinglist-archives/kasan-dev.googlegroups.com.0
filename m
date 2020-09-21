Return-Path: <kasan-dev+bncBCMIZB7QWENRB2OZUL5QKGQERLPC4XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 1673D2725BB
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:38:51 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id ic18sf6624211pjb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600695530; cv=pass;
        d=google.com; s=arc-20160816;
        b=DeUlG8EZWpaFapSTbLX6zFLAUWd4DkNE+OBI9Feb0x6JfzQoapx4d9KMj3RTxQQNgT
         Mo8KRID7sMU/dHN4j8BWpjTm7KdYzARZXXPdTIm0LgsKvGLzQHDW9tt1r1CkEwdFed8i
         sQ3ZKgduVWHPHOG8nvQ59kI45rVKhzCZvfYABGvcPQ1RwhcbN8ccaVugy6486LITrCPF
         LKOHA3NuCGBJfvAcG4skiqAxp+4z3sKITvY7qTaTpYqyFW43YDb4IysLB71Tpd71Sh4N
         Ft/xHVNWknQyQcxNLNEBRiPu0J61rAZSl9aPE4YlJEBicKBmqD3yE9ZRMRkkoXRkM5QE
         jPaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kXeDamQwb4hrWehBsLFdYJsxhvxSMAEh0hlEqO5MH94=;
        b=Pzj0+L/z6qfJB491KKx/sU1LfL3MDyE09jVo1LQu9Erz/gST3jjrR+z17mqQ+4N+Xm
         aSeRVToDTorBpU/ANBkhfVoVvWRPJdOh1nVWgZYKrbKxwyAGasN7CWDnUe/2PoIGN1AF
         WfE18cryIfup8xCJ8zpx0QXoJWNlztbrmC6ZBv/FwWoimPTw3hPwBMU8FETOsv1q9N+j
         GW4gCBf5Je//nDVB4E+qZLTyyT1oHc3HLgMKbu7iDuCFsFsmA4YtHdZhgsAKE0kyiZTs
         nBPDewp1sEQprMN8pd5aPxSQNWDzs2/+XDk9rmI3KIYY203Jw2XAfo9SKZogJg/dVUcO
         XWFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HNVQxdIv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kXeDamQwb4hrWehBsLFdYJsxhvxSMAEh0hlEqO5MH94=;
        b=pvcf4O9yQGpLry3YmWaEe+XIWa+l6Hq8BQk++RaxrKZPf2cY0KNDo6SZO8vqY0hbml
         AXBB8sBY1tsns6ZekfyjzlStkOmCny8JZh6oBrIdVMjMrxteqGvaS56xeK1f8tpI+a6s
         OW2OqP+EbYC4l9W3ru5oawS3QGeHmVEmOZX3oWr6kl2qfW0QmS5vycdYikyOYQVR49SM
         WfnyyQjF66jiQ+2Vleo9HYVAScDdmbJhU2rVAIHM1DeqrNzTrKZdcJXLKSTiMml2f193
         wc86cngE/0zRHrN9Co4S4COGxtOFx4meOJHMHOMUaNS/PwoEaX+MET2jTnUkScPUDr1k
         liGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kXeDamQwb4hrWehBsLFdYJsxhvxSMAEh0hlEqO5MH94=;
        b=k4SPC/Se9oyq2B7e8+HIfPLFi+qeGIjtHbE37+aEhfL8LYuaQjiCz6Eqr7gZ8g/VHl
         MUDGImiydGY60dOlukJcndfTSh7lB78EonI1g3WbOJutjCR4CF/NO7SIx+OXdzLCeugg
         33LKYWgnKu1k1HNshp9s7PutAeUpHsSzmTn1P1+SfEoHY3JE0fy4/h4jZkiY2ySi40Pl
         6ArvKf5D6IeWt5L5dJxtbnGSizAIccKgJzRbdGwVMko7c6Xn85wZr9BbliasyPCHMmfn
         YSopdNQgujgU5/k9vwybK61rOhPTM8/7GALyg9/quNNXq6mXO1cBsA28wYMnwMtQy89E
         w3rw==
X-Gm-Message-State: AOAM531uoFDgA5c6QITMKD1uZ+W9OgTLmqWAKLJ0DNEksbbjEIjWWSFw
	oWQS3R8C5XI80Ua2VuB6ZtU=
X-Google-Smtp-Source: ABdhPJx6Z9VNVMrD/6FPvWTLAizfUiQUQhMmTv8D+LK+0e80wZamrj7SzOAVMFvcBEu9ks3xEu+dPw==
X-Received: by 2002:a17:90a:ca8e:: with SMTP id y14mr24890156pjt.114.1600695529782;
        Mon, 21 Sep 2020 06:38:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d704:: with SMTP id y4ls5688339pju.3.canary-gmail;
 Mon, 21 Sep 2020 06:38:49 -0700 (PDT)
X-Received: by 2002:a17:902:c401:b029:d1:e603:1bf3 with SMTP id k1-20020a170902c401b02900d1e6031bf3mr27934816plk.47.1600695529183;
        Mon, 21 Sep 2020 06:38:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600695529; cv=none;
        d=google.com; s=arc-20160816;
        b=0drELvRnsc+H0o8XWw30x/pcqbLjCGMqcwFM6zp9akNnOmkv+PXuGVYKRdzPj5gqNJ
         +NNMxcOcWfgp8PKMa9I6V6qFVMycWSwDo/XPJpkF04RxWMNq4PF7Z/GwnlxiRoUx4DlR
         dwvVTzFkINxgNJ+GUjaqonFwuU35WcBj+OptnDFs4Sd+aU4tIpE+pd0ux22MDpTdCQ45
         k1KwQht7828m79tCzkKpBr98GozdIfNSFmYP8T3bGcRG3CQsOSHSz6bkYxBFOps1+Qb5
         5juqE1HV51j7jt/zF6Pfx3BisSbv+tTZXxEKOtUbk8Nautd8HwSwUIwIBr+B3US+czD7
         qOHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ERlr98dYkkda4zLxk53JkLPO7AhscnKPFqUfoBopbaA=;
        b=v4QMb838mDaWIrFMeY63SMlBYj7juJZntqpFHCyh2w5M9sEMl1MLrEX3HhL5EIl5IJ
         wG9y8nofnQZJRfhPwrFjb2vDnWp7YUGjJ9ZvcFJumV0DnSt4LdbAAuBefZZ5L2s/QGiZ
         9btgOLoaJ/aounJfjZPlTzbiXydDn3fFp+XhM2uUU5+MGvd7Vo/6ZL+vAbEl3rG3unwp
         vDs1JqORuvHwZGcULnoY7cZVKuhTz4Yspf/roQu/7agU6sGFqM2lWdiC3xPIAHhirNrR
         wLcz3Atb3IbkgynxBnM/cmltgDdBLtXs+gIfU5E0wIQJXMiBHT6Ff+7VvqNMmNs7sbX8
         nxzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HNVQxdIv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id mj1si790556pjb.3.2020.09.21.06.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id cr8so7287731qvb.10
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:38:49 -0700 (PDT)
X-Received: by 2002:a0c:a4c5:: with SMTP id x63mr36319qvx.58.1600695524500;
 Mon, 21 Sep 2020 06:38:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Sep 2020 15:38:33 +0200
Message-ID: <CACT4Y+a1PH_Pms=AZg_QwAd8_MzZDKyxUTxo0-GthiJyE-e4vg@mail.gmail.com>
Subject: Re: [PATCH v3 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan.Cameron@huawei.com, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HNVQxdIv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Mon, Sep 21, 2020 at 3:26 PM Marco Elver <elver@google.com> wrote:
>
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.

Hi Andrew,

I wanted to ask what we can expect with respect to the timeline of
merging this into mm/upstream? The series got few reviews/positive
feedback.

Thank you



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
>
> v3:
> * Rewrite SLAB/SLUB patch descriptions to clarify need for 'orig_size'.
> * Various smaller fixes (see details in patches).
>
> v2: https://lkml.kernel.org/r/20200915132046.3332537-1-elver@google.com
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
> 2.28.0.681.g6f77f65b4e-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba1PH_Pms%3DAZg_QwAd8_MzZDKyxUTxo0-GthiJyE-e4vg%40mail.gmail.com.
