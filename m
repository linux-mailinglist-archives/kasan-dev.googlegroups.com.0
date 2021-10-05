Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIHA6CFAMGQETW7OCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F0EA422403
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:45 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id b20-20020ab05f94000000b002ca067c0203sf2719808uaj.16
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431584; cv=pass;
        d=google.com; s=arc-20160816;
        b=LK+ty5o553WdnDfmWDlwXcH3NMKzHhmfX0wiVo+I9vxUpEFpzXBMWhBSX0jNpapq2u
         cvnMr1Fdgqr7EpubP+zs+WCOKOE1v9bCrKcL9EmFNlz+Kce3cPBhIo48tKCI6hbbg3oW
         AoOSmC1DhHW/7pYY+Qdvx1RgnpBdNoI7d54/AjZIad6oT7MRk5iDDk6k6FeZLPzkx5c+
         adIsfF4mlLIq6lQBGvrXv8d0C8eV179zHu8P48MQP629M/h9fhZ7pD44k77hzF4TrTAs
         PIgXtnByZG+YNWQAi/52A2Ked3XAAreuXevGULRxhGtmqkUA/+mqdEKfo4lcst6jhgjl
         921Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=V15cwwY9HGkcXgjJCU6BWkB8UP9T850ts3nWEe6puiY=;
        b=rsaI5Nl1ahkjn0lYEK0Hgl/l2MpQcbB8iJM4a6mv4fbq5zvwmRLx23qQxvyeni1+3A
         +dN503y0aTsfHLTF+sOrZ7clKZ4uqcKUlnxCag6IuKTHbxtIPVlYIcrLUVK/wjKmsRBy
         LKvo78neV1FUm3s+u23L2rWqkaW00OPhAZYWGQmqGrZHSgYODtTJvbnBwptQWTmOsV2X
         xTD75DCghx4HVXv4NR1GwHQ+xM4zIzodK97F3OJneAXBNWqiWcVj8wLA9ciz8+kMLBq0
         cDpHxRmxdyTXKZHZYcq5nRSkKCuOURHHGTvBqChD4s7H5HpQiMYRTpMJaBQvZAG8LfPT
         e6Qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="C+l/ThvU";
       spf=pass (google.com: domain of 3hzbcyqukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzBcYQUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=V15cwwY9HGkcXgjJCU6BWkB8UP9T850ts3nWEe6puiY=;
        b=ste/SFSCJJuWdrucodBn1GYSUzlKVqkm285kqhv9IqtY4CERpGMAqgJmNPGrR4wgmn
         WdSiaXxk3fkwn7UX/ym8vt9BSJq8w1P+ltTaPXlaf8hmQuLJ939O9xAE8c1/NPlU+oNR
         ABWXb6RsSq02pivEDQC8P0xSOn65g299ZZxUtloUad2TPrAt1l9GsWntPv8TAFmqUwaI
         cvTMeruTKQRFVgealdWoR4FG6kEOD4IbRobXepFSK5077oq0A9QIV1blSHnicibJRgSA
         PUTy7SSGOsv3ZIMffHPdZHYiD8gezniejq+nZWYmxzduV68oZ6omURSo9JunlTmevIpO
         6cmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V15cwwY9HGkcXgjJCU6BWkB8UP9T850ts3nWEe6puiY=;
        b=mKDUGBJwgpAI+XYWdSD2636uyZBpX0iv9vnl1Ml5MTHnLipperO6y6NRlWrCSkCJpW
         c+0o+co01fAvDVkLuF4kZE40MnMv/U4Jz2fGDXGsj74P8a4afucFcm6eYmtKjEstKaFi
         w12z70DVHeOHHfiRkQvaAnINRrdaL8DufOF1S2kMAAAGa/qIvYAqsNSBF9kU8qFAh+DD
         CF3R9irhkAUuOyQSpf4e0yz4zQs9D99AY76QYzjJpx4ckXDyGXYh2vKdkNHQODhE9LmG
         LMpg7BjWNVQCOJe9zQCCiSpuRRcu0lrImOYllpxxfYOepSuluZpIwBzMBvuvq37hHQVY
         GArg==
X-Gm-Message-State: AOAM532Hr7VAtisoMK9Y/AmaKzH78oHekoZtVoU/bBCto8tD5JvWJaqg
	QZ9yIDTRZs9CA4xm0ZcUgVI=
X-Google-Smtp-Source: ABdhPJzDXt0UC3r776VxVBVb9mc5b1mZRtRltClZKWEHepVvCJjJu2ggR5v3lTSrAv5OOCjahWB8Sw==
X-Received: by 2002:ab0:2404:: with SMTP id f4mr5340702uan.102.1633431584178;
        Tue, 05 Oct 2021 03:59:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6386:: with SMTP id y6ls2993903uao.4.gmail; Tue, 05 Oct
 2021 03:59:43 -0700 (PDT)
X-Received: by 2002:ab0:72cf:: with SMTP id g15mr6463308uap.5.1633431583637;
        Tue, 05 Oct 2021 03:59:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431583; cv=none;
        d=google.com; s=arc-20160816;
        b=Q0LaVjUUa5DhbOeUQHRRkBZiSW4FOrsUBN72usDM3jO3YWkZEk4pemFbmM6S4opKfs
         pWkw55325nICvxDTkMPpO4ee7hbjRwbb8W8tiLLiq58QNFJ3IPwAsvpIAdZuDZgdyl8A
         S9pfu6p+JJkt5k9MVfcHaX9NS9Ww6fqgt6MtcXx6rVX0Zxdhf2eh8i2vBLT+1KoQ22Dt
         IrOFs6Vl4yJsiEc+JI+5hiSviwcN5zijo1HtgQYwGud5lGMiOg9/gHceL5N8CnpfjXV/
         17pz8jum11CunIw0uVNm52VRrZEItNEhRu5q9JGYI4vKMbJ31AjGSAmoMABhFj9kwTNA
         9Rag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=7p97hglZNgfpwLYScP5gJSznCljkQgJf1oM6gC4sW1s=;
        b=FhYrUY6MYbRn5no/L/pKQfwrPcEzHEZM1CGsrCEYN2eiMwRYEUwl0TsCdlZyP0J8IM
         FROtWcb1KqVZ+GZ4Eoi99dGawl2a+hsjNowC0+9IcxmakWXbKT0b1agjHDV9BfzQBhef
         Hv9gFMVQ3Kp1+0sZwPoLcF5X2Wf498E5VeozFNWLAk5rm5n8pXYpagMTlsxAv69DJWxj
         l7vc5gtcJBFa8OSQnnt2Q5tcXZ7jilVVtPQkh9Nj4zRDcekisKIJlZ1121fo/fr6rjNG
         Wtyccwc4DHZGE5mzzKN2pCyHjaA4GJYPps3eQAbD9Th10HIB9eHeaBFMb2h00vUtMk7u
         SO9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="C+l/ThvU";
       spf=pass (google.com: domain of 3hzbcyqukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzBcYQUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i41si270095vkd.2.2021.10.05.03.59.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hzbcyqukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id w2-20020a3794020000b02903b54f40b442so26707671qkd.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:43 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a0c:aa15:: with SMTP id d21mr26637930qvb.18.1633431583153;
 Tue, 05 Oct 2021 03:59:43 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:42 +0200
Message-Id: <20211005105905.1994700-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 00/23] kcsan: Support detecting a subset of missing
 memory barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b="C+l/ThvU";       spf=pass
 (google.com: domain of 3hzbcyqukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzBcYQUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

The series is rebased on -rcu/kcsan. The objtool patches currently
conflict with pending changes in -tip/objtool/core, which could be
separated from this series if needed.

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

 Documentation/dev-tools/kcsan.rst             |  72 ++-
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
 tools/objtool/check.c                         |  36 +-
 24 files changed, 1240 insertions(+), 172 deletions(-)

-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-1-elver%40google.com.
