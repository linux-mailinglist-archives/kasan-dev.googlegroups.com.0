Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP45TCGQMGQEKO2OIIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F984632B8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:04 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id c14-20020a056512104e00b004036d17f91bsf7789955lfb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272704; cv=pass;
        d=google.com; s=arc-20160816;
        b=gMhY2P4SEER5YVU5zqs2Ohk2EIdB/HdRDAzKx3lpO1OI50n9S2XpVSOKYLoM9eHUgX
         B7Q7Jl9EBySDIuLBkcTBIFEhmTXv9zNFVXrkXP3FirkZXsCQQfj4IogZF+xRHpq2Iak6
         yDJk5Rg1qtSvg1pzoRpkRpZkM9kIpqHkU+yOGDdFrr8Zb+n3SUWVfIbxhhTCiK4lm+x3
         ZIAiS1FRnxhlAav33p9CINvWXvraW2bTvpsRlE34IfPJedGspnOcJ2ZFhYFivIGSPD3C
         U+0pJg1d/eh9od8UP6228B8V6evP5NMrGeB/UvgamoEGsZPYSnNkfMZAZ8mxP0JVmcRN
         Ap2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=whXa8YAQvxbxiHZF/ikHyFi7mTTXHemAfHlguzheVYo=;
        b=BoxqvsU55HQt58Zs9WNgdOAixF0xz8ZoBy4XVciNnL012xBLge0qVx58P0+aRfpB7l
         /2FlNkZjWQQhUlCqPG7UZQTE63us2a+0BActwim44yF/avv6vSoCNsyvdXyJrwsd/Ix7
         mWH+6txz44mIrGEaw8UYh9UV4bpKislEwfkAWODlyDlUwIiBcmAKCyeQz9s78bhnSNcJ
         6KLfppEsrrVPFBB5EZVXafZMgDOXf7lRHBNdo4Sy7mCNijLS5NhFGM0rhCbdK9cTislc
         N5lYcRGMPhiJxfpmDUa8ulmZ0/gk5bBIMVood9Yld28QQMSQ455pCqeY3zZZPa1JoKAL
         yy9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IL7CAFvV;
       spf=pass (google.com: domain of 3vg6myqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vg6mYQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=whXa8YAQvxbxiHZF/ikHyFi7mTTXHemAfHlguzheVYo=;
        b=AdPIhRA2VFO9T2QRR3FaiByYs8BOa/T3mjS9ozLA9rvFhzgDU9SonCwNsHTsZJtd9P
         GkEIzJ6uP3Iai+YcQPVQEqFZ3JiPViWNt6El14rUZ5aZBrTC7czyMJKqVeAI+h3R564w
         vr63KdrKfhf+7CbKuK1hsA3aK06fJsXdkgW+UVIE8G/4W1GsIBuH7Ix8Bn8NUGMvnEl6
         rpUINOQLKcgkVITyYE01W0no8JEjL5ZJDMBre3fq4GtZScgij8gvCmX28zJtKdRkSKWB
         LwGxnewh4i5jrbEzZ0thZV54H3hax2Zxp+GXfTsuZA3WHyUbEyRHxNOCMe12ByiQ4pxx
         jF9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=whXa8YAQvxbxiHZF/ikHyFi7mTTXHemAfHlguzheVYo=;
        b=cJm7enSApS6D5jGYMgORMGq9i2/ox1JYkumpHlGgKuEfJXXPFlkYb59DfyfhOaHnQ7
         /pJpJa2L31eTgxtXrofsmAfILOVruj2vce9085TH2gqrySXtbvLF8ev1B68P/f+bHInn
         Sm4rMABnpnjDhXTqY5I0xVMbmzpI0kRgEN0hZX2buaMq4NBJ7uaD9pvCWcM8gtgNKFdF
         OA8zT5ICtdZM8M9BOoRHWzyLdThfx233fCSdBVF4d5Qsql1goeOogd4D/hfkOnTSK0xf
         dmH40FUIqSY/uZejGloZfjMVXnuy8IyQgZlBTTPeu6iNssUrJywyepuIowO5iee7iLMi
         7FnQ==
X-Gm-Message-State: AOAM531Sh/9HFY79QGfpoWpW3DzERr33kzhHD/1CdR54VHkD6X9Z5eTg
	CxddCARckVuhEj+BqCDRs4g=
X-Google-Smtp-Source: ABdhPJzVIfUZDx0F/9DWtA2tFylMNarB/n+FX+pdgF4TPlm8R46FZ87RlrkbpGMM1Dcy3eTrpDzLfw==
X-Received: by 2002:a19:5052:: with SMTP id z18mr54313870lfj.23.1638272704071;
        Tue, 30 Nov 2021 03:45:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1687:: with SMTP id bd7ls2437823ljb.10.gmail; Tue,
 30 Nov 2021 03:45:03 -0800 (PST)
X-Received: by 2002:a2e:2206:: with SMTP id i6mr54976561lji.357.1638272702953;
        Tue, 30 Nov 2021 03:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272702; cv=none;
        d=google.com; s=arc-20160816;
        b=weT6BT4o0Idgz/ggvoi4dmbBIKu9Qfgp7w8h5yWArKNwBRcXlYEqsORPq5oFgzBfUs
         wDz44m0brp/4GgKAKCyYKByT8yZkrsiEjGVXU6H8yMEmk0JqgVl8fCqzBI42zLO6XHFT
         SelU63eRmlvSVWrM6UVhcH6QRPso3v91yC0OCMFMVmD25Ylev6Q2/VHcbgrqSnL6fydS
         5lYZat/tokQTXySEESb5kcb3zqV4egdUahkD4+21d3pEFOIJi1yR6Cnnjwc3mGPbcoCK
         8LhJ7AUigbs5i3z6RN5QOgTQgUMh4IV7XMMJ8JPA2/BArRW90o/elraZe6kwKR/1Bcal
         diVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=bYDosMGyIXEijQF2/XlnbLPYOrdGKyrE1hTUivhL4CU=;
        b=JDsHlwRMG7oRsdjmNV6SELF/HgELjFWrplTEkzPaQ7bnrZdCD++++SBBonhvnKqlDQ
         T9f/IFmQN+csAk3kq7RElSmh6ZDebOlHSCMs0KDtPInGXchf+Zn29Cu6J67oGOQlpgcB
         omUini9ped1KuT9NymMo+h4kpyc9Xft7ebNKuaU3j37T0N+N2wNhax0F7YzGBVuNQApC
         4j2BL1JiR7gfXPwk0AQMBzV/aJ2AOx1mabiFmLUPg3pKkjheM3BUNIr09NTiAmzy8q94
         EcM6LC36cXTgLIHkwgX/lrQ7oipaQuYAGDPqjY2Nnxp2Y+J3qPI5myfEmllP27/sAA5O
         D82A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IL7CAFvV;
       spf=pass (google.com: domain of 3vg6myqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vg6mYQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id h12si1551209lfv.4.2021.11.30.03.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vg6myqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203so12698003wms.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:02 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:1990:: with SMTP id
 t16mr4315850wmq.48.1638272702321; Tue, 30 Nov 2021 03:45:02 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:08 +0100
Message-Id: <20211130114433.2580590-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 00/25] kcsan: Support detecting a subset of missing memory barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org, Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IL7CAFvV;       spf=pass
 (google.com: domain of 3vg6myqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vg6mYQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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
for some currently uninstrumented subsystems.

Followed by objtool changes to add the usual entries to the uaccess
whitelist, but also instruct objtool to remove memory barrier
instrumentation from noinstr code (on x86), given not all versions of
Clang currently respect __no_kcsan (== __no_sanitize_thread) for the new
instrumentation.

The last 2 patches (new in v3) fix up __no_kcsan for newer versions of
Clang, so that non-x86 architectures can enable weak memory modeling
with Clang 14.0 or newer.

Changelog
---------

v3:
* Rework to avoid kcsan_noinstr hackery, because it is unclear if
  this works on architectures like arm64. A better alternative exists
  where we can get __no_kcsan to work for barrier instrumentation, too.
  Clang's and GCC's __no_kcsan (== __no_sanitize_thread) behave slightly
  differently, which is reflected in KCSAN_WEAK_MEMORY's dependencies
  (either STACK_VALIDATION for older Clang, or GCC which works as-is).
* Rework to avoid inserting explicit calls for barrier instrumentation,
  and instead repurpose __atomic_signal_fence (see comment at
  __tsan_atomic_signal_fence), which is handled by fsanitize=thread
  instrumentation and can therefore be removed via __no_kcsan.
* objtool: s/removable_instr/profiling_func/, and more comments per
  Josh's suggestion.
* Minimize diff in patch removing zero-initialization of globals.
* Don't define kcsan_weak_memory bool if !KCSAN_WEAK_MEMORY.
* Apply Acks.
* 2 new patches to make it work with Clang >= 14.0 without objtool,
  which will be required on non-x86 architectures.

v2: https://lkml.kernel.org/r/20211118081027.3175699-1-elver@google.com
* Rewrite objtool patch after rebase to v5.16-rc1.
* Note the reason in documentation that address or control dependencies
  do not require special handling.
* Rename kcsan_atomic_release() to kcsan_atomic_builtin_memorder() to
  avoid confusion.
* Define kcsan_noinstr as noinline if we rely on objtool nop'ing out
  calls, to avoid things like LTO inlining it.

v1: https://lore.kernel.org/all/20211005105905.1994700-1-elver@google.com/
---

Alexander Potapenko (1):
  compiler_attributes.h: Add __disable_sanitizer_instrumentation

Marco Elver (24):
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
  kcsan: Support WEAK_MEMORY with Clang where no objtool support exists

 Documentation/dev-tools/kcsan.rst             |  76 +++-
 arch/x86/include/asm/barrier.h                |  10 +-
 arch/x86/include/asm/qspinlock.h              |   1 +
 include/asm-generic/barrier.h                 |  54 ++-
 .../asm-generic/bitops/instrumented-atomic.h  |   3 +
 .../asm-generic/bitops/instrumented-lock.h    |   3 +
 include/linux/atomic/atomic-instrumented.h    | 135 +++++-
 include/linux/compiler_attributes.h           |  18 +
 include/linux/compiler_types.h                |  13 +-
 include/linux/kcsan-checks.h                  |  81 +++-
 include/linux/kcsan.h                         |  11 +-
 include/linux/sched.h                         |   3 +
 include/linux/spinlock.h                      |   2 +-
 init/init_task.c                              |   5 -
 kernel/kcsan/Makefile                         |   2 +
 kernel/kcsan/core.c                           | 345 ++++++++++++---
 kernel/kcsan/kcsan_test.c                     | 415 ++++++++++++++++--
 kernel/kcsan/report.c                         |  51 ++-
 kernel/kcsan/selftest.c                       | 141 ++++++
 kernel/sched/Makefile                         |   7 +-
 lib/Kconfig.kcsan                             |  20 +
 mm/Makefile                                   |   2 +
 scripts/Makefile.kcsan                        |  15 +-
 scripts/Makefile.lib                          |   5 +
 scripts/atomic/gen-atomic-instrumented.sh     |  41 +-
 tools/objtool/check.c                         |  41 +-
 tools/objtool/include/objtool/elf.h           |   2 +-
 27 files changed, 1330 insertions(+), 172 deletions(-)

-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-1-elver%40google.com.
