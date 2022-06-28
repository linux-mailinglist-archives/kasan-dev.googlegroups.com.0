Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZFB5OKQMGQE57NY4JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 647B055BFF2
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:01 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id i23-20020a2e9417000000b0025a739223d1sf1518682ljh.4
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410340; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8oMLkR6rFI7xSJVYUXY8MTvgL3yzeUMhClPC3wmPugOxZWYwAJuqOuG/SvmtrYeJe
         vdRtB+KKkUwDtAUnbdc2hZ4AuOCcBhdb0Xr0XvUJBEhUaY9PvQzV9hcskIvsQ02a5C48
         +I2+qPo4i/iKdIZpjVMosUbSKGy+GE8KqJswFU2Y8fBxlNQzMHO9u0j4NCNVklZHgvQG
         wEH60/YUznwQBwu17pr7wTJ4KcmHTSRUfPkMbWncVsJ65H3nhVmsjXwKhuaQ38nWWN7y
         0uhdJM1MhOsQ4R1S1OojheuT4DMght9VNZj9EktlGv+sYYB1V5C9m+dVavKW95viHm81
         824w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=s+SFm2RYIRPOdq13vqKnpg7NUmnQZETuOOcYMZdebVI=;
        b=lmzl3rQFF+qb9zduJKKyFc7SN+9aArWQ5iF/aT9YpAWhpZniOkXZI/d02Jir/h4G21
         6nNtV2Z6xkNMul6a4iWU2OvEMqQlhug0KXHnhAlrdmf7y7uitmyQcn5RUxC/j5YEblJm
         mVgZj65te6QygPlqA7MvfjbNFYN5peYXyF5xSfA5SguCnZMH3d303eSOfDIamJDQCt/p
         9cJbYvi94ksGCbzvM6D9aoYTQMpLkXf6Ee3RmlmXo4K26U2CtjqK5onbgdpDjSl1keuZ
         3fUH6wyl4ZBkSXtReHDz2iG951QiXYWaKfY3IR15VIbFqK4BC0Bn62CTILAjKNG5zk75
         rsmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kpac3JTW;
       spf=pass (google.com: domain of 34tc6ygukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=34tC6YgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=s+SFm2RYIRPOdq13vqKnpg7NUmnQZETuOOcYMZdebVI=;
        b=EifUtiMVbS10zjOq3M42UmqcxKda2CV03bDrLT13AzHyzlqCY1oorF4RGf9WN/4bxM
         9L/b88gtSSdaV69OkNxOIa+mvkbthCpjxVkpLp7DFpwXdK+cSSBitU7eMShDGIyqL6/X
         hWTQq+0M1wi6OukB3Yl7UhmRPjUW/5XB7wWX2MlZZuWPvy3Xve1V9OzchKTwwca+GQCN
         7vECUbdB3orI0mgqA2KzGYuxXhwV3u/B/CRGbQ144aYMHIJ17Z+YDyMMJ07F3T5ZTvVU
         IGD1wbhGooBbA89fxXqiw6kyU4q2ZvWqvltM/IPgJB6I++dI/gt1SZwwRQdqGYOjmeLK
         PaMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s+SFm2RYIRPOdq13vqKnpg7NUmnQZETuOOcYMZdebVI=;
        b=pN41/mWU2KPCxHj/0mSOOCt3eJp8L17VJQ0LDUgmO2GxPzRXj/bbPy3l3uOje9CLIS
         VuimhPffLqmaRBLUcAvcB3geil0wH4RduicTuqzj6c/uhc5mKDxaQjN9sn31Slc51UqN
         dYkZ74emLuzu0VemBSqDb7ud/SuPWqpC3loFpIJRIqvnHeRnG++3OxwOpU64OrVw+GFe
         c7GRlsQkEGsDOz6OOyPZ0qNUCoQtlJp0u2itf8FD1uppskmmtZYTZN39ynIS6I0ZJCMr
         MSZLbpH8P7T9Qqj9Rjd+5yiXjn2+r0o+ee221Ev4i/e3hjkmRPG7WEfFgHhCSTxnFpeT
         0ohA==
X-Gm-Message-State: AJIora9t0DlNVCRj5Ct1fjLc0AwJt46qTIKg+lqCgOW5/mW001MN9xqA
	t1escMQU5LLtILiQmy5NtUI=
X-Google-Smtp-Source: AGRyM1vSh73wA043UkJf6UjqifHPWKntNsTRtxDlZPK+Akj4dCnKD04spIkOHyZtnliuDsaQVDKckQ==
X-Received: by 2002:a05:6512:6d4:b0:47f:74b4:4ec4 with SMTP id u20-20020a05651206d400b0047f74b44ec4mr10664918lff.654.1656410340538;
        Tue, 28 Jun 2022 02:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls288487lfv.3.gmail; Tue, 28 Jun 2022
 02:58:59 -0700 (PDT)
X-Received: by 2002:ac2:5d31:0:b0:47d:c71c:50d5 with SMTP id i17-20020ac25d31000000b0047dc71c50d5mr10724946lfb.665.1656410339064;
        Tue, 28 Jun 2022 02:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410339; cv=none;
        d=google.com; s=arc-20160816;
        b=dk0KLXa4lQf4P5OIyweo9NelZ0zNoIzDaTwYQ/iA/syZtiVeIY43Ne7MnQVlfFuX8G
         kPz6m0RmWkPco7sr6z0VSmj9cmi0+6j/XIc2+bqykge3n+JoZj2llLBC4w1gLB/BOB9w
         DXh4LdaRdnd7s/AGkA7J5Ehbj03FgJdnCVxGrc1AZadfaBbamFQeFC0sv0wTAzkdDr8+
         J5hCzWsjVXS+92X/0MMx91HEFL+hjCtKvPFwOU4iqEH4a3gc/8HRbQD/fXqInxu92J+f
         9khUu72n46kUjnLnyFwv7ySg3T0zcu/WJvbcDn5jhC35FWRsKZNeGPGp8tftD+sNaxbO
         vaiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=MrF5aaShEN6B7UjaZWC1TSqA3Z20kM5d1l/pRL2xCe0=;
        b=GqgaVR/YEHEDs06WScJeP3WFS7ovnDU1BkpUh/shMgrRyZsCTPaCCKr5xKeiZjToBu
         0lDQNVUHVo6tQQ4Pq6PuFrJL2XzTwJTL+L4EOUi2ITfkIh/ooGKPTut5eaVPu3ju2/O1
         bqChWZxyeaXvHzgQ4oE36ODOvlO+eRupNNCr7kHISypiaC8OmTkiP96ULehwsYlxuQGj
         21nKtjHqBABbskJSslzCdpGSD+qIa0MrhOJgtNjX+IsTruXhVCGNfpenLK7V+p40+gXR
         YX7m3tMDf7nkrUUAPDJLJkHBSu+0mb48X4Sefs0j/cgzzKRUgBKsB2RlhH8l9bntBgDs
         Mm3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kpac3JTW;
       spf=pass (google.com: domain of 34tc6ygukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=34tC6YgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bd10-20020a05651c168a00b0025a72c1807dsi530984ljb.2.2022.06.28.02.58.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34tc6ygukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qk8-20020a1709077f8800b00722fcbfdcf7so3408110ejc.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:58:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a05:6402:1c09:b0:435:6562:e70d with SMTP id
 ck9-20020a0564021c0900b004356562e70dmr21782463edb.203.1656410338427; Tue, 28
 Jun 2022 02:58:58 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:20 +0200
Message-Id: <20220628095833.2579903-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 00/13] perf/hw_breakpoint: Optimize for thousands of tasks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kpac3JTW;       spf=pass
 (google.com: domain of 34tc6ygukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=34tC6YgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

The hw_breakpoint subsystem's code has seen little change in over 10
years. In that time, systems with >100s of CPUs have become common,
along with improvements to the perf subsystem: using breakpoints on
thousands of concurrent tasks should be a supported usecase.

The breakpoint constraints accounting algorithm is the major bottleneck
in doing so:

  1. toggle_bp_slot() and fetch_bp_busy_slots() are O(#cpus * #tasks):
     Both iterate through all CPUs and call task_bp_pinned(), which is
     O(#tasks).

  2. Everything is serialized on a global mutex, 'nr_bp_mutex'.

The series progresses with the simpler optimizations and finishes with
the more complex optimizations:

 1. We first optimize task_bp_pinned() to only take O(1) on average.

 2. Rework synchronization to allow concurrency when checking and
    updating breakpoint constraints for tasks.

 3. Eliminate the O(#cpus) loops in the CPU-independent case.

Along the way, smaller micro-optimizations and cleanups are done as they
seemed obvious when staring at the code (but likely insignificant).

The result is (on a system with 256 CPUs) that we go from:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
	 	[ ^ more aggressive benchmark parameters took too long ]
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 236.418 [sec]
 |
 |   123134.794271 usecs/op
 |  7880626.833333 usecs/op/cpu

... to the following with all optimizations:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 |      Total time: 0.067 [sec]
 |
 |       35.292187 usecs/op
 |     2258.700000 usecs/op/cpu

On the used test system, that's an effective speedup of ~3490x per op.

Which is on par with the theoretical ideal performance through
optimizations in hw_breakpoint.c (constraints accounting disabled), and
only 12% slower than no breakpoints at all.

Changelog
---------

v2:
 * Add KUnit test suite.
 * Remove struct bp_busy_slots and simplify functions.
 * Add "powerpc/hw_breakpoint: Avoid relying on caller synchronization".
 * Add "locking/percpu-rwsem: Add percpu_is_write_locked() and percpu_is_read_locked()".
 * Use percpu-rwsem instead of rwlock.
 * Use task_struct::perf_event_mutex instead of sharded mutex.
 * Drop v1 "perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent".
 * Add "perf/hw_breakpoint: Introduce bp_slots_histogram".
 * Add "perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent task targets".
 * Add "perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task targets".
 * Apply Acked-by/Reviewed-by given in v1 for unchanged patches.
==> Speedup of ~3490x (vs. ~3315x in v1).

v1: https://lore.kernel.org/all/20220609113046.780504-1-elver@google.com/

Marco Elver (13):
  perf/hw_breakpoint: Add KUnit test for constraints accounting
  perf/hw_breakpoint: Clean up headers
  perf/hw_breakpoint: Optimize list of per-task breakpoints
  perf/hw_breakpoint: Mark data __ro_after_init
  perf/hw_breakpoint: Optimize constant number of breakpoint slots
  perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
  perf/hw_breakpoint: Remove useless code related to flexible
    breakpoints
  powerpc/hw_breakpoint: Avoid relying on caller synchronization
  locking/percpu-rwsem: Add percpu_is_write_locked() and
    percpu_is_read_locked()
  perf/hw_breakpoint: Reduce contention with large number of tasks
  perf/hw_breakpoint: Introduce bp_slots_histogram
  perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent
    task targets
  perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task
    targets

 arch/powerpc/kernel/hw_breakpoint.c  |  53 ++-
 arch/sh/include/asm/hw_breakpoint.h  |   5 +-
 arch/x86/include/asm/hw_breakpoint.h |   5 +-
 include/linux/hw_breakpoint.h        |   1 -
 include/linux/percpu-rwsem.h         |   6 +
 include/linux/perf_event.h           |   3 +-
 kernel/events/Makefile               |   1 +
 kernel/events/hw_breakpoint.c        | 594 ++++++++++++++++++++-------
 kernel/events/hw_breakpoint_test.c   | 321 +++++++++++++++
 kernel/locking/percpu-rwsem.c        |   6 +
 lib/Kconfig.debug                    |  10 +
 11 files changed, 826 insertions(+), 179 deletions(-)
 create mode 100644 kernel/events/hw_breakpoint_test.c

-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-1-elver%40google.com.
