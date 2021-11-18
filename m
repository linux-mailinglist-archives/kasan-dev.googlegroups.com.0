Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEUV3CGAMGQEMXXBU3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B004F45564E
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:10:58 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf3443729lfv.11
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:10:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223058; cv=pass;
        d=google.com; s=arc-20160816;
        b=aPBLWnGcPz4kGSqzXIR5HY3wM4me2wbvfYTKMgYeOsGrq62ITM/33Gyt2lzQjpkMG8
         lNFmtgeMjQ/eLQoMzAXPxdAJyz6Ke7CmNwIWvjxohJVYdVp68KK8q00tXdMp8BAPoBiM
         pSanPXjmeNgkTqEUvywk0m+5Ic8DQwUFYG7vlfJqyzb84DMTfLSf6aCk23wZsb3qVFak
         +UH3fGtcjjSOIiE9LjR0yuYRydSuONY9/iAD3AqkOWDhuHSeRt7h2yIuTjKBDmeaTgk/
         phRY33jAtrXkg7TGCFGT6F/ghb1wbWv3oyR8UWnmMfeexnge1ejhY9LVsgHTd5LlVydn
         TbEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=GOQWqU3cTRMDy9CerUA9yBwaxZkTejP6kVI9UHgv9wg=;
        b=ktnnnHIOpUb/z3toiL/vckCqFylzr8D8IU6wNJZ48Sg0j3MulG6yhiiFiwWSPPkPnB
         YuXNd3R5knwFbHGBuaHDnZFsgJC1UPH4eQg/hHDgBKSQwasGBz0fMd2r1Lfg6VZc3HF2
         vcry+uiHYLtIAitaJF7c2NzM178qMgP2cXuGacefdOh0saQrNWnebhcZnhyy1mRlNmvP
         UPpGcBUphz53awmurYi70KJebHHkiBejh2/plxeyrFSz9JPu5EQkLM2bXE+n7CuGS2WY
         L6b5ceXLIdrQwJ73AL7Ov91se2yRplBjiVfyMGpjyTecT3yPQRDtlgwQjuNJEkEpqQkz
         NrFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="qEJtN/Dk";
       spf=pass (google.com: domain of 3kaqwyqukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kAqWYQUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GOQWqU3cTRMDy9CerUA9yBwaxZkTejP6kVI9UHgv9wg=;
        b=Mpg8vX++dJt08mxFFkGjCB9OYBqusLLqTSR+GXQ22k+maDh0ckKLal6thtNYvGRwkQ
         MPwe/Zs7PpGpRsUYm9UJVE1JTBo0UqdwseRb4uAeK48eX9aEljfEeFc5yyfVCcEmeiTF
         UF6QmDsBEElYKZPrCOGjlKNZIyHBuPsINykRajuZp8pevRbbLgAixwkrpNM08PmKHjkM
         xwIGfIElmjMqTmoCCOdM8IyzsZWV18qVp1ikwPQ7eldkIIMTJ61C3sbkZFC7F1/7Lka2
         KPsNLpE0mxQU1lMGRXMh5Ge63SzOcZ3U2RXZMoNGmNPoe1sJzwq2jWHRAuJPdw81CvD/
         EVzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GOQWqU3cTRMDy9CerUA9yBwaxZkTejP6kVI9UHgv9wg=;
        b=qhYNBREKSCqB40qiK/58+tRI4HsFU8TSgiHbIOdpAydxp9N3swpeitry3Jg7AOB3yb
         AsEz7KWEnz8xGK1XNTYJJ7Fd/owYdq1wEQas/jJOFAm0d0bOWUOaylyVnTWs0IpJEojT
         149HC9wF9ev8gN6CKznsizfWzddQgnV5Foq9OZ2xxDyTfMx7J7AxVUgoKj+r3RYd3M9Z
         hr09XQhtocBtP0USp5eGxbZtg6wCY4glWL3ngzBQaDCWM6nRFIGHs6bvZ5sCgVeYXR+9
         SjJ+xdeb2NGs+wPhGVnKqjlYkNtJnI7imTQk9kO3D/iKyZ2FACnV0ayA2jQs2tk1NQme
         SVTQ==
X-Gm-Message-State: AOAM530/bDNlV0oNOvH/ddXTSDX2kmt0oyVw85rGt519BITbNqi3nbds
	l871OJcfepybgPzhSbxmNUk=
X-Google-Smtp-Source: ABdhPJwvv7G5Mo697/BFdNcIXXd8xdOsr16qyc/hgyTNlKMNCJa8y5jp5DcncZ53CsFrvXaqpuh7bA==
X-Received: by 2002:a19:48d7:: with SMTP id v206mr22634155lfa.102.1637223058235;
        Thu, 18 Nov 2021 00:10:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls1612786lfr.0.gmail; Thu,
 18 Nov 2021 00:10:57 -0800 (PST)
X-Received: by 2002:ac2:4e89:: with SMTP id o9mr22223793lfr.384.1637223057168;
        Thu, 18 Nov 2021 00:10:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223057; cv=none;
        d=google.com; s=arc-20160816;
        b=ocZ3Hr7rA+84R75H36yeLsl7foh7l/1WCs7zOoUKNgLSfAdwGCHKu3a+137t8QRdj1
         lEMqjBybIIuYkhBYjB17QeXt4vz+s53FfgrdyR2pnl0DwkavgeJbq+utqBNYJ7zHsxlv
         +Q/Zcdmb4a4IBXcqiRZ5YRYu8OrzM7trwsoYeADXrXF1+Hchn3+viATPAXURzE85O/ig
         AP75nCSGheanZCScWlJPFtFxT2ibOo9ASaezEYK3Rqi/aoSA+PgIDyfMdbxV7KFacyEr
         yNkxplPxZLZ/g0JAWwf6aeJiiQfH2FUQTLSDe2XwEmFMYr0IOCQ36SIwfm2Dpwc5t/ND
         zrEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Xzmo5mL9yKPgm1lZgxwsGIqYX+i9650OydzQnMolJjY=;
        b=D64bTVC6NZa5wWmxNpF/MTkL7EX//bsBC4+GvYEa2VXSYower8dL6tUpdFLrVG7DHW
         WtO6G+OhrOwNqEUdnOklhH6q+7j4ztCezD0wwZu1csdCDfUwJMS0AVhuSCeVFKnyOC7E
         vCLWTqy3mA5cb58SIeG94t3xbzAJaScxrQx/MyWIejkYKiSqv8cNodqIw7f6LvmEaIxo
         nFgl6ICWmIohjli2rdNweLE3bZyyI/G587HJSAmQUPJdaW0R1TkLlGYi0psoK9NH1E0y
         bKwYRtfOa9pZteicnARQF1fYvh7F3CuoSSdorgr1O0O/FtMXQ4Q7dTWzW0cXL9vqgFda
         +qNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="qEJtN/Dk";
       spf=pass (google.com: domain of 3kaqwyqukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kAqWYQUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id b29si167734ljf.6.2021.11.18.00.10.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:10:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kaqwyqukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dso1757267wmc.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:10:57 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a5d:4e52:: with SMTP id r18mr26521150wrt.224.1637223056499;
 Thu, 18 Nov 2021 00:10:56 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:04 +0100
Message-Id: <20211118081027.3175699-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 00/23] kcsan: Support detecting a subset of missing memory barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="qEJtN/Dk";       spf=pass
 (google.com: domain of 3kaqwyqukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3kAqWYQUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

Detection of some missing memory barriers has been on the KCSAN feature
wishlist for some time: this series adds support for modeling a subset
of weak memory as defined by the LKMM, which enables detection of a
subset of data races due to missing memory barriers.

KCSAN's approach to detecting missing memory barriers is based on
modeling access reordering. Each memory access for which a watchpoint is
set up, is also selected for simulated reordering within the scope of
its function (at most 1 in-flight access).

We are limited to modeling the effects of "buffering" (delaying the
access), since the runtime cannot "prefetch" accesses. Once an access
has been selected for reordering, it is checked along every other access
until the end of the function scope. If an appropriate memory barrier is
encountered, the access will no longer be considered for reordering.

When the result of a memory operation should be ordered by a barrier,
KCSAN can then detect data races where the conflict only occurs as a
result of a missing barrier due to reordering accesses.

Some more details and an example are captured in the updated
<Documentation/dev-tools/kcsan.rst>.

Some light fuzzing with the feature also resulted in a discussion [1]
around an issue which appears to be allowed, but unlikely in practice.

[1] https://lkml.kernel.org/r/YRo58c+JGOvec7tc@elver.google.com


The first half of the series are core KCSAN changes, documentation
updates, and test changes. The second half adds instrumentation to
barriers, atomics, bitops, along with enabling barrier instrumentation
for some currently uninstrumented subsystems. The last two patches are
objtool changes to add the usual entries to the uaccess whitelist, but
also instruct objtool to remove memory barrier instrumentation from
noinstr code (on x86).

---

v2:
* Rewrite objtool patch after rebase to v5.16-rc1.
* Note the reason in documentation that address or control dependencies
  do not require special handling.
* Rename kcsan_atomic_release() to kcsan_atomic_builtin_memorder() to
  avoid confusion.
* Define kcsan_noinstr as noinline if we rely on objtool nop'ing out
  calls, to avoid things like LTO inlining it.

v1: https://lore.kernel.org/all/20211005105905.1994700-1-elver@google.com/

Marco Elver (23):
  kcsan: Refactor reading of instrumented memory
  kcsan: Remove redundant zero-initialization of globals
  kcsan: Avoid checking scoped accesses from nested contexts
  kcsan: Add core support for a subset of weak memory modeling
  kcsan: Add core memory barrier instrumentation functions
  kcsan, kbuild: Add option for barrier instrumentation only
  kcsan: Call scoped accesses reordered in reports
  kcsan: Show location access was reordered to
  kcsan: Document modeling of weak memory
  kcsan: test: Match reordered or normal accesses
  kcsan: test: Add test cases for memory barrier instrumentation
  kcsan: Ignore GCC 11+ warnings about TSan runtime support
  kcsan: selftest: Add test case to check memory barrier instrumentation
  locking/barriers, kcsan: Add instrumentation for barriers
  locking/barriers, kcsan: Support generic instrumentation
  locking/atomics, kcsan: Add instrumentation for barriers
  asm-generic/bitops, kcsan: Add instrumentation for barriers
  x86/barriers, kcsan: Use generic instrumentation for non-smp barriers
  x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
  mm, kcsan: Enable barrier instrumentation
  sched, kcsan: Enable memory barrier instrumentation
  objtool, kcsan: Add memory barrier instrumentation to whitelist
  objtool, kcsan: Remove memory barrier instrumentation from noinstr

 Documentation/dev-tools/kcsan.rst             |  76 +++-
 arch/x86/include/asm/barrier.h                |  10 +-
 arch/x86/include/asm/qspinlock.h              |   1 +
 include/asm-generic/barrier.h                 |  54 ++-
 .../asm-generic/bitops/instrumented-atomic.h  |   3 +
 .../asm-generic/bitops/instrumented-lock.h    |   3 +
 include/linux/atomic/atomic-instrumented.h    | 135 +++++-
 include/linux/kcsan-checks.h                  |  51 ++-
 include/linux/kcsan.h                         |  11 +-
 include/linux/sched.h                         |   3 +
 include/linux/spinlock.h                      |   2 +-
 init/init_task.c                              |   9 +-
 kernel/kcsan/Makefile                         |   2 +
 kernel/kcsan/core.c                           | 326 +++++++++++---
 kernel/kcsan/kcsan_test.c                     | 416 ++++++++++++++++--
 kernel/kcsan/report.c                         |  51 ++-
 kernel/kcsan/selftest.c                       | 141 ++++++
 kernel/sched/Makefile                         |   7 +-
 lib/Kconfig.kcsan                             |  16 +
 mm/Makefile                                   |   2 +
 scripts/Makefile.kcsan                        |  15 +-
 scripts/Makefile.lib                          |   5 +
 scripts/atomic/gen-atomic-instrumented.sh     |  41 +-
 tools/objtool/check.c                         |  41 +-
 tools/objtool/include/objtool/elf.h           |   2 +-
 25 files changed, 1248 insertions(+), 175 deletions(-)

-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-1-elver%40google.com.
