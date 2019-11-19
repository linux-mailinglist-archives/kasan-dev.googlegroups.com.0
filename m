Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBUEZ2HXAKGQEJIEV4DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0421F102D4B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 21:13:06 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id a129sf14285730qkg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 12:13:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574194384; cv=pass;
        d=google.com; s=arc-20160816;
        b=P2mraIh2BmroHOIXs1dzFHjNA8AwyDG0CknTOuUvoayR6+AiQiiIYJjrJ/f2E6iPKJ
         xAuVYPgmSMTc3Nlx5gOBpny/yE+6sPPgmnqSdHMHTm3DyUMDyQFIFCyAsabsJH5V+1Ma
         1UgDhC4SIx1GMvF+ptFosfklLx1X2KEXzHWukdhhRLAzg2Zwkz70pfKhnzlFM6szdFCy
         p3J2I1q9vOgqx6OeXaMD2SE7EwBuDLetCqXmmXbF2kBybXb3oFDshnt5tx8nWdj+RFMw
         q4nI/Qm60szFxDd602cu4VFzOVR+xSXaU/Pbmlt4PgqSa9dmGXfby6IAFK4fIuRwc2TG
         LRKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=1wyoMlkwt9/UBdhHUbxjxr+cVX9UaWqMdxWVn9fu9So=;
        b=0GGfDvJluZTAagsEpw2EN2l7W+Xt7jT+UykKgRjyjdwRH2I5uyVuIOcrArPzcgEBM7
         SKS8ds0AAMwApZUdOLTttpB+zH1rPyHPa/lf86k+o1rLxT8wQKmhWkyErcFP1h8CmvqY
         K9KS2R30QC2CAVJbtZPqjg2F1z7By0QA0yAVz4B/z2zDbDAuzdwOrdw64j2pXf2JF1Ve
         PMpxgon0NHX3FWNC9AEEZ2emz9tDCbnQyV/BQYDfDN/biY7eSdNltiLzqF/Koy4Gpt4m
         EFmERKmIBjvQHkQ+f5KqG7NeKsC/jSn403pnNPIfibedGnYSXMzpD3lOET08tbawdOa7
         6VNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=pmg80JZE;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wyoMlkwt9/UBdhHUbxjxr+cVX9UaWqMdxWVn9fu9So=;
        b=EFro3nC355tJMJ0k7TLHq/yvo8jg0dASV8+t8lfStRsPgJBkvlw6OLz7hsibFN4uCs
         ki0Ewq0xI1ikTgsKqBob9b/PxG63f01wXj6Sm0fMGbPijh87me+9BLxj+HgE+dWmnuE9
         qmzGEptS96nKdRUEsmTDReDgi9/gXEkZ6AJcWm2IP4ZVamxMJxcf8XEv0ZLLORpBZJLD
         71qEmewxUqjwwWLzv0fci9B4Oi5avu7KIixx1THxSVoXPkQCb0FH61OhvZKfJXe4LDlO
         BXJto8etxscz4GzytU2+Z/K0Or/DAONCnI5CFlbH/g8pk/2NgN0o2gvj3dZSqg34+7M4
         MI9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wyoMlkwt9/UBdhHUbxjxr+cVX9UaWqMdxWVn9fu9So=;
        b=c97ujQPKjZu3S1KXmdgfLwkAr7wHEhCj0DctcJgS8Vh773TVyk5bZO110qlMdLmAiG
         Rw1fvEnSOlMgB4UsdpffTUMgNxMHfeaB5oApC69WX1yJImTGaWrG+LINaSoYpdqg0r8r
         lZ2n1rFKkc8RKOzFqX6bA9OLiaMX3O0+qGdtrI+tbjOu+hxxNdPAI9agz7f6jDtKdSLd
         Zx70+1CB4InjZC+Zptrv+oJ7F7CyWumklkIJ2b61xOP5Y9ZQJ4ZwQ+9qouZk7ozefZem
         P+RL+/9YXTxdt72GQqMjfZQBpzuZ4RTfZN/ZPzU73GYv7YvoyN+KZ8EAy4GmSWP/jeUS
         OdZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgQ1h5tX3MBz6mJGy0QZjj5hXQDwIt+3UcvoR59hdPJtkbRHP/
	N4FE+YDCIa6I2BuAyzURm+o=
X-Google-Smtp-Source: APXvYqyhSYs1JE4SNKQkws3kY4WcFHrhqyHdJIheQRnDNeTom+EfNMK7XbaMN1VU6QbE9gxZVH/RFw==
X-Received: by 2002:a37:2716:: with SMTP id n22mr7738054qkn.500.1574194384561;
        Tue, 19 Nov 2019 12:13:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:18c9:: with SMTP id o9ls6543545qtk.3.gmail; Tue, 19 Nov
 2019 12:13:04 -0800 (PST)
X-Received: by 2002:ac8:4517:: with SMTP id q23mr35114421qtn.359.1574194384128;
        Tue, 19 Nov 2019 12:13:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574194384; cv=none;
        d=google.com; s=arc-20160816;
        b=G+58FEvmh3QttYcPORvs83VD/NR+VU6Puy593G+MF+vhe3SE9zBfZ90psJjLWVNEq8
         ydsLs2H9IJeoEbZpdVmI1VZLOLzMuGpnnOQX+LBm4xtR8cGu+e4Gzb1/7pGtKgrI3C7I
         B6828tIPj0yQYW5K7uxNRF3pY/tAyEoo6mH3J6Q/QuNzpXxLvQmH3DGlBHNyjGhmPQQW
         4aaV7LmraPDYiQNtKjyGQpKHHwBwMtzFztTITPisiGKNsUAZou8fxiBhf66RQQA/wGSy
         bxgFC9zLpf3yXgM0jZ/XsLOI10QG2Ap221mkVPNxUyKqqQREn3nNj7H587TY1XnTtbyK
         J+7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=Dwf1aPW+I4uJ8oN51QPPu2dFggZ3HdhgD621r7zy2tg=;
        b=XwHsrDEjNwO9FF/Ei8ce9O8hv/WJEsZYVaF6cVBmlZUIBv25HCVDN9QgFzbSOAwXyP
         kDjofRG2Rh13WfYsVSyGA/emJig7a8a8MJBl8sLANZ/TovccvpwFZDrl6q3TG7l3ptV5
         GLmA12e8kM0XQBcDe73hJo4ju9vfMTOtEC8c5wbZzXoSSf3LdZJjxn+VgNhrNw2vwU9b
         415CCxrgrUhhnmALNXfzgRpENoKTdng5g6THN3cGp5sY1r0mRqT9b0lyyd+XbN6jvMly
         sGCNshVplpNte7uSPCFBtITguQrRu+w2HIYExPVkBWIO3KSS512oX+763aT6mm1FjYvO
         qzDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=pmg80JZE;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id y41si1503290qtb.5.2019.11.19.12.13.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 12:13:04 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 30so26088491qtz.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 12:13:04 -0800 (PST)
X-Received: by 2002:ac8:22c4:: with SMTP id g4mr34398685qta.45.1574194383599;
        Tue, 19 Nov 2019 12:13:03 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id i10sm11900621qtj.19.2019.11.19.12.13.00
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 12:13:02 -0800 (PST)
Message-ID: <1574194379.9585.10.camel@lca.pw>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
 parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
 ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
 bp@alien8.de,  dja@axtens.net, dlustig@nvidia.com,
 dave.hansen@linux.intel.com,  dhowells@redhat.com, dvyukov@google.com,
 hpa@zytor.com, mingo@redhat.com,  j.alglave@ucl.ac.uk,
 joel@joelfernandes.org, corbet@lwn.net, jpoimboe@redhat.com, 
 luc.maranget@inria.fr, mark.rutland@arm.com, npiggin@gmail.com,
 paulmck@kernel.org,  peterz@infradead.org, tglx@linutronix.de,
 will@kernel.org, edumazet@google.com,  kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org,  linux-doc@vger.kernel.org,
 linux-efi@vger.kernel.org,  linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,  x86@kernel.org
Date: Tue, 19 Nov 2019 15:12:59 -0500
In-Reply-To: <20191114180303.66955-1-elver@google.com>
References: <20191114180303.66955-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=pmg80JZE;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:
> This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> KCSAN is a sampling watchpoint-based *data race detector*. More details
> are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> only enables KCSAN for x86, but we expect adding support for other
> architectures is relatively straightforward (we are aware of
> experimental ARM64 and POWER support).

This does not allow the system to boot. Just hang forever at the end.

https://cailca.github.io/files/dmesg.txt

the config (dselect KASAN and select KCSAN with default options):

https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

> 
> To gather early feedback, we announced KCSAN back in September, and have
> integrated the feedback where possible:
> http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> 
> The current list of known upstream fixes for data races found by KCSAN
> can be found here:
> https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> 
> We want to point out and acknowledge the work surrounding the LKMM,
> including several articles that motivate why data races are dangerous
> [1, 2], justifying a data race detector such as KCSAN.
> 
> [1] https://lwn.net/Articles/793253/
> [2] https://lwn.net/Articles/799218/
> 
> Race conditions vs. data races
> ------------------------------
> 
> Race conditions are logic bugs, where unexpected interleaving of racing
> concurrent operations result in an erroneous state.
> 
> Data races on the other hand are defined at the *memory model/language
> level*.  Many data races are also harmful race conditions, which a tool
> like KCSAN reports!  However, not all data races are race conditions and
> vice-versa.  KCSAN's intent is to report data races according to the
> LKMM. A data race detector can only work at the memory model/language
> level.
> 
> Deeper analysis, to find high-level race conditions only, requires
> conveying the intended kernel logic to a tool. This requires (1) the
> developer writing a specification or model of their code, and then (2)
> the tool verifying that the implementation matches. This has been done
> for small bits of code using model checkers and other formal methods,
> but does not scale to the level of what can be covered with a dynamic
> analysis based data race detector such as KCSAN.
> 
> For reasons outlined in [1, 2], data races can be much more subtle, but
> can cause no less harm than high-level race conditions.
> 
> Changelog
> ---------
> v4:
> * Major changes:
>  - Optimizations resulting in performance improvement of 33% (on
>    microbenchmark).
>  - Deal with nested interrupts for atomic_next.
>  - Simplify report.c (removing double-locking as well), in preparation
>    for KCSAN_REPORT_VALUE_CHANGE_ONLY.
>  - Add patch to introduce "data_race(expr)" macro.
>  - Introduce KCSAN_REPORT_VALUE_CHANGE_ONLY option for further filtering of data
>    races: if a conflicting write was observed via a watchpoint, only report the
>    data race if a value change was observed as well. The option will be enabled
>    by default on syzbot. (rcu-functions will be excluded from this filter at
>    request of Paul McKenney.) Context:
>    http://lkml.kernel.org/r/CANpmjNOepvb6+zJmDePxj21n2rctM4Sp4rJ66x_J-L1UmNK54A@mail.gmail.com
> 
> v3: http://lkml.kernel.org/r/20191104142745.14722-1-elver@google.com
> * Major changes:
>  - Add microbenchmark.
>  - Add instruction watchpoint skip randomization.
>  - Refactor API and core runtime fast-path and slow-path. Compared to
>    the previous version, with a default config and benchmarked using the
>    added microbenchmark, this version is 3.8x faster.
>  - Make __tsan_unaligned __alias of generic accesses.
>  - Rename kcsan_{begin,end}_atomic ->
>    kcsan_{nestable,flat}_atomic_{begin,end}
>  - For filter list in debugfs.c use kmalloc+krealloc instead of
>    kvmalloc.
>  - Split Documentation into separate patch.
> 
> v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> * Major changes:
>  - Replace kcsan_check_access(.., {true, false}) with
>    kcsan_check_{read,write}.
>  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
>  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
>    contexts.
> 
> v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> 
> Marco Elver (10):
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure
>   include/linux/compiler.h: Introduce data_race(expr) macro
>   kcsan: Add Documentation entry in dev-tools
>   objtool, kcsan: Add KCSAN runtime functions to whitelist
>   build, kcsan: Add KCSAN build exceptions
>   seqlock, kcsan: Add annotations for KCSAN
>   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
>   asm-generic, kcsan: Add KCSAN instrumentation for bitops
>   locking/atomics, kcsan: Add KCSAN instrumentation
>   x86, kcsan: Enable KCSAN for x86
> 
>  Documentation/dev-tools/index.rst         |   1 +
>  Documentation/dev-tools/kcsan.rst         | 256 +++++++++
>  MAINTAINERS                               |  11 +
>  Makefile                                  |   3 +-
>  arch/x86/Kconfig                          |   1 +
>  arch/x86/boot/Makefile                    |   2 +
>  arch/x86/boot/compressed/Makefile         |   2 +
>  arch/x86/entry/vdso/Makefile              |   3 +
>  arch/x86/include/asm/bitops.h             |   6 +-
>  arch/x86/kernel/Makefile                  |   4 +
>  arch/x86/kernel/cpu/Makefile              |   3 +
>  arch/x86/lib/Makefile                     |   4 +
>  arch/x86/mm/Makefile                      |   4 +
>  arch/x86/purgatory/Makefile               |   2 +
>  arch/x86/realmode/Makefile                |   3 +
>  arch/x86/realmode/rm/Makefile             |   3 +
>  drivers/firmware/efi/libstub/Makefile     |   2 +
>  include/asm-generic/atomic-instrumented.h | 393 +++++++-------
>  include/asm-generic/bitops-instrumented.h |  18 +
>  include/linux/compiler-clang.h            |   9 +
>  include/linux/compiler-gcc.h              |   7 +
>  include/linux/compiler.h                  |  57 +-
>  include/linux/kcsan-checks.h              |  97 ++++
>  include/linux/kcsan.h                     | 115 ++++
>  include/linux/sched.h                     |   4 +
>  include/linux/seqlock.h                   |  51 +-
>  init/init_task.c                          |   8 +
>  init/main.c                               |   2 +
>  kernel/Makefile                           |   6 +
>  kernel/kcsan/Makefile                     |  11 +
>  kernel/kcsan/atomic.h                     |  27 +
>  kernel/kcsan/core.c                       | 626 ++++++++++++++++++++++
>  kernel/kcsan/debugfs.c                    | 275 ++++++++++
>  kernel/kcsan/encoding.h                   |  94 ++++
>  kernel/kcsan/kcsan.h                      | 108 ++++
>  kernel/kcsan/report.c                     | 320 +++++++++++
>  kernel/kcsan/test.c                       | 121 +++++
>  kernel/sched/Makefile                     |   6 +
>  lib/Kconfig.debug                         |   2 +
>  lib/Kconfig.kcsan                         | 118 ++++
>  lib/Makefile                              |   3 +
>  mm/Makefile                               |   8 +
>  scripts/Makefile.kcsan                    |   6 +
>  scripts/Makefile.lib                      |  10 +
>  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
>  tools/objtool/check.c                     |  18 +
>  46 files changed, 2641 insertions(+), 206 deletions(-)
>  create mode 100644 Documentation/dev-tools/kcsan.rst
>  create mode 100644 include/linux/kcsan-checks.h
>  create mode 100644 include/linux/kcsan.h
>  create mode 100644 kernel/kcsan/Makefile
>  create mode 100644 kernel/kcsan/atomic.h
>  create mode 100644 kernel/kcsan/core.c
>  create mode 100644 kernel/kcsan/debugfs.c
>  create mode 100644 kernel/kcsan/encoding.h
>  create mode 100644 kernel/kcsan/kcsan.h
>  create mode 100644 kernel/kcsan/report.c
>  create mode 100644 kernel/kcsan/test.c
>  create mode 100644 lib/Kconfig.kcsan
>  create mode 100644 scripts/Makefile.kcsan
> 
> -- 
> 2.24.0.rc1.363.gb1bccd3e3d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574194379.9585.10.camel%40lca.pw.
