Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVOW3XAKGQEKZYNP3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F5A0FCC7A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:03:59 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id d11sf2199096lfj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:03:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754639; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZUcv1SklxEIChAjEb3Bv6PxLXy0fUgfAtcERjtHtm/JrkftkWSSou1wkq6T6olRK0n
         +N5HoIE0aontAecKRPOd314TBLyiKblLgLMbch4xgBvDQuGmF+9Q11Gtor0bQArtjjVM
         6NT8dROupcbbp8X3kB1lJYRdeb69DJxeVZDAC+hDSymqVuH+3YdgoLiKS05jpa2+Suep
         bBhhn0npBgl+ZpWn4nBLaqA9us2Dxr1D4DLcf2FLYzAHCIEdKqp94COtrA8rZLBu1PF6
         BeTzRnaoBO1XPimN9z5BCCME99oQ2bBNccfpDrXoi++UiiUfeye4lPaZ/Rlmd+JXz9ev
         ffLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=mu7JT5Yboa6tlufPbH55KAcLkrmxqzB+7E8c48QDhhU=;
        b=ECVcDtf8cySpuYDWi+mIAbwFtEik/Z5B2S06y/fFiQXnO1nz1h64PkyJXD9SrlhWqS
         qsOlm8faGYbrPA25wNSHGknTGMqJfBuGuly2JbnAF0qkZn2Kn12aS4uA+lyA3+DbMxKT
         xc/V5BS8/aBfm0h7HAPtnMsQ/cgdLqEb9L6BmnZbMGjwNQtgYaLpJudtp/HorHtDE/uq
         BAuWuf4ZpbWtmLL9scl33gR0QL8S9oZoe3RLs/ENOx8FN3qMLpHYj1IbF3TxnM8nO9Yl
         JFP9DTMHi7qrhDicIQc8hVTiEyFCodgsdONZ2Izg0y4D/FFYKN6DSyRSNSl0Ng8QY7lW
         ZaAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="lr7v9t/b";
       spf=pass (google.com: domain of 3dzfnxqukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DZfNXQUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mu7JT5Yboa6tlufPbH55KAcLkrmxqzB+7E8c48QDhhU=;
        b=opernJTooQn400u3qVwc/4eQqv7qJ2VOnK+cAndSeO6xYAMQNgz1JizQuhqBwXsmwW
         P2drCZeF5hIJdhZEJQPFN1WFzJuQM/L5VjwP34mXuznYOztxRK3WRAxEGCTZSQKnd9zg
         LvIn3kNFswTyL8ld7h4ULcxX9a3O0a58gly180acTz69Xz79kimpspnhQOWOh21n7wPM
         m0FPjKhLYoRQsNwReNsCThpjlDycTd3XhQ1GUhPCrrBIxGJQQr8mi/IrRIb6z0rj36tJ
         QIqufhSgEkP75XNHF1OiRgMfx9wP1XPAv5psoqhCzojdfq3TY9KzihQHa7AVzqSPA2O2
         BLgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mu7JT5Yboa6tlufPbH55KAcLkrmxqzB+7E8c48QDhhU=;
        b=GFjl63Krv0jaeFgvn/srlur6pQACta9GzHAYVLhbC6WaJMxsHjlpZTFdZ2xaV3Ne0U
         En6sEWpTXn07jJXFbIaO20b+I3UKWGqdykHweS4K9qNP2ApN9cUreq0+FUjg+CBonfWK
         lWvj7WO/HsPhK7y3oHKuNAy0FFqalJu3xVQeNP6oGjkjXA/EYOS1KUBuIvvclPcmPaM+
         JvHi6ftCxdNL13RxzyNfzGdFmVKwVnsUAC8ilwpl1pOfh7D6SU3OeHAYioSyXVH/Js4O
         SEHQquNRYZ90WWMfhmIViRDvDFEQcS2wAZxyqPC3abCozX0sCKr5r7FfOd2S7Tb8Fq4w
         YycQ==
X-Gm-Message-State: APjAAAWSjs1Ckf7vagGVqGjnB6xn+k5/tHmBuhQwdJRmZImko3La0eHE
	4rdoyfpXANVTf9JZWMLaFnI=
X-Google-Smtp-Source: APXvYqwpmriAWURzQGgL1UDQDPgVrw9xlqCjOwNOqmyq+RS0n5577sEodVjdpjH6bWSt2A5rJMyEog==
X-Received: by 2002:a19:c18d:: with SMTP id r135mr7829446lff.75.1573754638855;
        Thu, 14 Nov 2019 10:03:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:7c:: with SMTP id i28ls1041628lfo.0.gmail; Thu, 14
 Nov 2019 10:03:58 -0800 (PST)
X-Received: by 2002:ac2:4856:: with SMTP id 22mr7978422lfy.131.1573754638151;
        Thu, 14 Nov 2019 10:03:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754638; cv=none;
        d=google.com; s=arc-20160816;
        b=V3MM/wqC31CZ6LbaUf7ReBfWqYaFi94kpR/UuENVGSjwNYAXwGMP4/rarlQ0JnU2M7
         65CrbgzIiNAtHXM9qVDCwWqHshqHPWNIp0EOqQ5+kQDQroNTnUF0mnntbVIgdwxM8soq
         U0+STz3SIH/77Fkoi9w3wR7hGbyONWN5CYtubpaiNX7E1w+U/liDEmeKzbotoKzEeAFp
         4Fy2l7WqCyJx9qnEihz7D566par5vypeGa0F7V/V3saBBSRQ0BKRG7OfzyOake41aNDg
         H6RMVW0ylQKMRpDBcqlYX44I4Ck1XmBVbUUsg4nBwEnb3ZSoC0XqTYzdSS++X9gnSf3n
         HZuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=1bg0Urry1BGwaxpDX8MHZFNgYP5IGRugkAlFUvPLa/I=;
        b=D0X/CpuD0ukQsyGzieURueda2bVeNct8EEnI/+11PbwrK/sMDIQXCocnhDG+DiTnmi
         V5twFt+rUvSe/O/4hnmVsd0xJaDaWxuKlrsB1usnzsj+f0VKHBy/KX3GWqTqPxl8rz6V
         2z14z0+nfLT0SWS5r0kaQlIQoe/c93+yKlu0eK+nKQoeSqCqrvanE1/OOJznAz+iesBS
         460qTYVmyRFTYwrR4vdxisYsAxyeeWF605abqd3rvFmzHurmrUDMvi7Nau3pCtVSH86p
         2qAaxKfAKXCD2/bD1QA9fOmqGimMjTxScNjD2/+wCUY4Pl7QANteJViwCQd0Wmoopljo
         MJMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="lr7v9t/b";
       spf=pass (google.com: domain of 3dzfnxqukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DZfNXQUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t3si245737ljj.1.2019.11.14.10.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:03:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dzfnxqukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id f14so3757796wmc.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:03:58 -0800 (PST)
X-Received: by 2002:a5d:4585:: with SMTP id p5mr9720266wrq.134.1573754637105;
 Thu, 14 Nov 2019 10:03:57 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:53 +0100
Message-Id: <20191114180303.66955-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="lr7v9t/b";       spf=pass
 (google.com: domain of 3dzfnxqukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DZfNXQUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
KCSAN is a sampling watchpoint-based *data race detector*. More details
are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
only enables KCSAN for x86, but we expect adding support for other
architectures is relatively straightforward (we are aware of
experimental ARM64 and POWER support).

To gather early feedback, we announced KCSAN back in September, and have
integrated the feedback where possible:
http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com

The current list of known upstream fixes for data races found by KCSAN
can be found here:
https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan

We want to point out and acknowledge the work surrounding the LKMM,
including several articles that motivate why data races are dangerous
[1, 2], justifying a data race detector such as KCSAN.

[1] https://lwn.net/Articles/793253/
[2] https://lwn.net/Articles/799218/

Race conditions vs. data races
------------------------------

Race conditions are logic bugs, where unexpected interleaving of racing
concurrent operations result in an erroneous state.

Data races on the other hand are defined at the *memory model/language
level*.  Many data races are also harmful race conditions, which a tool
like KCSAN reports!  However, not all data races are race conditions and
vice-versa.  KCSAN's intent is to report data races according to the
LKMM. A data race detector can only work at the memory model/language
level.

Deeper analysis, to find high-level race conditions only, requires
conveying the intended kernel logic to a tool. This requires (1) the
developer writing a specification or model of their code, and then (2)
the tool verifying that the implementation matches. This has been done
for small bits of code using model checkers and other formal methods,
but does not scale to the level of what can be covered with a dynamic
analysis based data race detector such as KCSAN.

For reasons outlined in [1, 2], data races can be much more subtle, but
can cause no less harm than high-level race conditions.

Changelog
---------
v4:
* Major changes:
 - Optimizations resulting in performance improvement of 33% (on
   microbenchmark).
 - Deal with nested interrupts for atomic_next.
 - Simplify report.c (removing double-locking as well), in preparation
   for KCSAN_REPORT_VALUE_CHANGE_ONLY.
 - Add patch to introduce "data_race(expr)" macro.
 - Introduce KCSAN_REPORT_VALUE_CHANGE_ONLY option for further filtering of data
   races: if a conflicting write was observed via a watchpoint, only report the
   data race if a value change was observed as well. The option will be enabled
   by default on syzbot. (rcu-functions will be excluded from this filter at
   request of Paul McKenney.) Context:
   http://lkml.kernel.org/r/CANpmjNOepvb6+zJmDePxj21n2rctM4Sp4rJ66x_J-L1UmNK54A@mail.gmail.com

v3: http://lkml.kernel.org/r/20191104142745.14722-1-elver@google.com
* Major changes:
 - Add microbenchmark.
 - Add instruction watchpoint skip randomization.
 - Refactor API and core runtime fast-path and slow-path. Compared to
   the previous version, with a default config and benchmarked using the
   added microbenchmark, this version is 3.8x faster.
 - Make __tsan_unaligned __alias of generic accesses.
 - Rename kcsan_{begin,end}_atomic ->
   kcsan_{nestable,flat}_atomic_{begin,end}
 - For filter list in debugfs.c use kmalloc+krealloc instead of
   kvmalloc.
 - Split Documentation into separate patch.

v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
* Major changes:
 - Replace kcsan_check_access(.., {true, false}) with
   kcsan_check_{read,write}.
 - Change atomic-instrumented.h to use __atomic_check_{read,write}.
 - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
   contexts.

v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com

Marco Elver (10):
  kcsan: Add Kernel Concurrency Sanitizer infrastructure
  include/linux/compiler.h: Introduce data_race(expr) macro
  kcsan: Add Documentation entry in dev-tools
  objtool, kcsan: Add KCSAN runtime functions to whitelist
  build, kcsan: Add KCSAN build exceptions
  seqlock, kcsan: Add annotations for KCSAN
  seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
  asm-generic, kcsan: Add KCSAN instrumentation for bitops
  locking/atomics, kcsan: Add KCSAN instrumentation
  x86, kcsan: Enable KCSAN for x86

 Documentation/dev-tools/index.rst         |   1 +
 Documentation/dev-tools/kcsan.rst         | 256 +++++++++
 MAINTAINERS                               |  11 +
 Makefile                                  |   3 +-
 arch/x86/Kconfig                          |   1 +
 arch/x86/boot/Makefile                    |   2 +
 arch/x86/boot/compressed/Makefile         |   2 +
 arch/x86/entry/vdso/Makefile              |   3 +
 arch/x86/include/asm/bitops.h             |   6 +-
 arch/x86/kernel/Makefile                  |   4 +
 arch/x86/kernel/cpu/Makefile              |   3 +
 arch/x86/lib/Makefile                     |   4 +
 arch/x86/mm/Makefile                      |   4 +
 arch/x86/purgatory/Makefile               |   2 +
 arch/x86/realmode/Makefile                |   3 +
 arch/x86/realmode/rm/Makefile             |   3 +
 drivers/firmware/efi/libstub/Makefile     |   2 +
 include/asm-generic/atomic-instrumented.h | 393 +++++++-------
 include/asm-generic/bitops-instrumented.h |  18 +
 include/linux/compiler-clang.h            |   9 +
 include/linux/compiler-gcc.h              |   7 +
 include/linux/compiler.h                  |  57 +-
 include/linux/kcsan-checks.h              |  97 ++++
 include/linux/kcsan.h                     | 115 ++++
 include/linux/sched.h                     |   4 +
 include/linux/seqlock.h                   |  51 +-
 init/init_task.c                          |   8 +
 init/main.c                               |   2 +
 kernel/Makefile                           |   6 +
 kernel/kcsan/Makefile                     |  11 +
 kernel/kcsan/atomic.h                     |  27 +
 kernel/kcsan/core.c                       | 626 ++++++++++++++++++++++
 kernel/kcsan/debugfs.c                    | 275 ++++++++++
 kernel/kcsan/encoding.h                   |  94 ++++
 kernel/kcsan/kcsan.h                      | 108 ++++
 kernel/kcsan/report.c                     | 320 +++++++++++
 kernel/kcsan/test.c                       | 121 +++++
 kernel/sched/Makefile                     |   6 +
 lib/Kconfig.debug                         |   2 +
 lib/Kconfig.kcsan                         | 118 ++++
 lib/Makefile                              |   3 +
 mm/Makefile                               |   8 +
 scripts/Makefile.kcsan                    |   6 +
 scripts/Makefile.lib                      |  10 +
 scripts/atomic/gen-atomic-instrumented.sh |  17 +-
 tools/objtool/check.c                     |  18 +
 46 files changed, 2641 insertions(+), 206 deletions(-)
 create mode 100644 Documentation/dev-tools/kcsan.rst
 create mode 100644 include/linux/kcsan-checks.h
 create mode 100644 include/linux/kcsan.h
 create mode 100644 kernel/kcsan/Makefile
 create mode 100644 kernel/kcsan/atomic.h
 create mode 100644 kernel/kcsan/core.c
 create mode 100644 kernel/kcsan/debugfs.c
 create mode 100644 kernel/kcsan/encoding.h
 create mode 100644 kernel/kcsan/kcsan.h
 create mode 100644 kernel/kcsan/report.c
 create mode 100644 kernel/kcsan/test.c
 create mode 100644 lib/Kconfig.kcsan
 create mode 100644 scripts/Makefile.kcsan

-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-1-elver%40google.com.
