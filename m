Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHLWKMAMGQEQDFSMVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B3BF5A4C35
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:01 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id p8-20020a056512234800b0048b12cb7738sf2017341lfu.6
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777280; cv=pass;
        d=google.com; s=arc-20160816;
        b=y9Qnew31WoYB4+GHo1p4gItzMjG3JPOmEnzwcXWHFtb8Gaduhs8ooZaxwyl8RDGxQa
         exKj8Nz5tmBId9n+sBxdUcEIgYyi8c2wB2eNSxlIihdgCuxhlOcW5PD0jJyCC5tGXiJG
         C7xiNFaYfq5Or4PzwEhsxFA76PmDahiELV9B2Ric+oDGZVDGCS8CxBHEfb872y+q5lBq
         P41Cuv6ZUC6sKL9RsHznFRFrEnHiPgj7WjDaJuArPR0tKP9rqnVRMQ+ef0zJ6V2vntF+
         OeBn3lL3x60BkesZM9QBoXkoPuio4UmxUBcGylofkgu2C4jN7yJWQ0k7S46RJxUEcJJZ
         OKMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=9xrSVYjX924VNJbj/SvkcQZFCz18tVzSo4wMZYbTtU8=;
        b=sLLBiiSC/cFdoJTGAuziINF+FUfdzMYS/OGaLDWh2TIhhHDQ8PTjt1XiuImVh+11tp
         DTIyy6TF8yyVNsTa07w2ddpEmOsoTNSZf5NNDyKysY9Fg58U+J/ZXBGhNfR5pm+kTPrz
         fFlcLLJj7t+gI8sDT6KjrvlzwcfX4938jYYMteXknATkqgY8UjLkgPRNNjtlHPUboXWa
         gk+CsfKmo6MdMEha8boNcvdm14rur84kRcWt7iuSQpKDW6rMz1gnY4+AZA6eCv7eJk3U
         2vCioCx7DRcih7LjDNB9BjJlzpI/lElipddwPxurN6WXvC+WF9I4VxCVxO3uV2yR+wCu
         UFVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AEnnVlL+;
       spf=pass (google.com: domain of 3frumywukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3frUMYwUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc;
        bh=9xrSVYjX924VNJbj/SvkcQZFCz18tVzSo4wMZYbTtU8=;
        b=oFudrqeeb4xv0glh6/jx/JfaI42Jdgn6eaAQ8h5sC99zyu8NGnzZzVN2/I9AmzHZ2F
         Au9dR9Lzw+TrYpXlsk/IcDUsKkcZ2vAIJk1E1rN601D+9rbYPPzVYzoRlE0j1j2Tgw/a
         yx6QuBYX0mCBUPwWfnM07ikCbaFgccGMi4kQIw7iycLDs4DyV+FXF1CmEIUMCUvz9qyH
         9XcOFkG9e+oV3E4X3m/juqO8vzZY4+MX2H2vd0wkapfyAulDdhzauTP0s7BcRKSC3viv
         671Wuk9vbzjDrjpV/n45uPGKkEfRdvZLlZtaBu3QT6c3YkDgJkGWmRxrMEo0tPaDf4eM
         hETg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc;
        bh=9xrSVYjX924VNJbj/SvkcQZFCz18tVzSo4wMZYbTtU8=;
        b=zeYomsbCnc/IFRWq5AAHwbNuM4QcGfHBFOnOBphOZw8HRfmZhd8o+IDLhUdoZNWQMx
         +4qfLPLiNAc/LoCVKUsJQktiVTMi/DrURuPZvUjVJYlNOcqeroLTrB78IQ0/S70onsik
         jfWBA/KwlwRJkEO5kSCkxMzwXYkygl/7mw2KipG3qmHZ8DmjiS7n1vjuPfXvATPee81Z
         rNCgj5WJeOVqoVRpNmWCf8C8SX7vW+XGBD6Vsy8E2i+6FT7XR32EECqjy6mbn+zwHGeW
         ZQeHM0HgXnKYMLISl0RSqnrYL+b1A/9T084tg5+53ZrNaG0QeekJql9LjlxrBYZQqN5K
         ZUHg==
X-Gm-Message-State: ACgBeo0lkx0G0+MCqSaJGCMlvfFAs/Y8xCvaMdRSAAqwF1W5yi4vRWQc
	7HNuUXjRVApmjOVZzgV0r5Y=
X-Google-Smtp-Source: AA6agR7KnrqrTtUdjbl29qlgdkrlWJDVMGXb/gUWuJOk/9OpD06yIQuDnI9A4acO5cCfTyt31/tUNg==
X-Received: by 2002:a05:651c:1544:b0:25f:5036:ece2 with SMTP id y4-20020a05651c154400b0025f5036ece2mr6062644ljp.73.1661777280485;
        Mon, 29 Aug 2022 05:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e33:0:b0:48b:2227:7787 with SMTP id o19-20020ac25e33000000b0048b22277787ls1485977lfg.3.-pod-prod-gmail;
 Mon, 29 Aug 2022 05:47:59 -0700 (PDT)
X-Received: by 2002:ac2:592c:0:b0:494:6adb:634f with SMTP id v12-20020ac2592c000000b004946adb634fmr1920013lfi.89.1661777278915;
        Mon, 29 Aug 2022 05:47:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777278; cv=none;
        d=google.com; s=arc-20160816;
        b=VmscEw12NflTeztsm3/raVsWcYPbLTi49Pxem5BTWPhsksyuwX/3Frfr3ZRZFF4sRt
         UpRI4+UVpuxo7IbrLaBSOBcYu1A1QoK197SCpNSpyAXX89/8MCZGg9XoWPUC6b6ul994
         c7+M6Z79vSW67Idsm0Mqy6g45xhJaufdspuTWirtTMNH/LDwM8WF+UYQdgoAk/emkmph
         bhnULXwBbVKfl86aXxfpGddOe6wMHkY2EkS0Ee0Y7XVWtWV6AL4vSr+Ixmx8TUjWbhnv
         2pFXgwTzIqc7MNjwhyi3iROUNkK/vJK4dEE3nAc/IQ91CsMctw2nmCBsKQm+caeulxZH
         997g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=j9ioItL4hhuJk4q9fk8sTyuu8wzwxxiWo3yP0IVLpNU=;
        b=Ff20MoDp4tYXq2P7l3CpmvBxFlEk6VKsS4/c5jD6bHsMoVTasr9AJX68nFHrxw6q/I
         fG3r1bhMpPM1c3RkBVnbWCtwIty9df1SqeB6PPp1W7XyGuvGG2rkkqbf04eqlIk9YtFV
         8fW1aekQg8hSwEfyTFXz728YOdi6pGNDHeFF3VB+a+V61C/u/JcRBUtaiG6LIWlXJAxF
         T1rLsxUMPLBFhFn+9sUzFxQwSvmyv7po9LILuP5H+Pdgv0eNwfd2IiNr27loiXEOu8E0
         9Brn0ZjXraWJgZLLHERj407NLoSCT0Eo36Qyst/o7UE7ZA55sJ9QzIvLko94qxYEUv+t
         MGcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AEnnVlL+;
       spf=pass (google.com: domain of 3frumywukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3frUMYwUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si3769ljm.2.2022.08.29.05.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:47:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3frumywukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sh44-20020a1709076eac00b00741a01e2aafso942522ejc.22
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:47:58 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a05:6402:350e:b0:448:4918:af81 with SMTP id
 b14-20020a056402350e00b004484918af81mr6393841edd.384.1661777278181; Mon, 29
 Aug 2022 05:47:58 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:05 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-1-elver@google.com>
Subject: [PATCH v4 00/14] perf/hw_breakpoint: Optimize for thousands of tasks
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
 header.i=@google.com header.s=20210112 header.b=AEnnVlL+;       spf=pass
 (google.com: domain of 3frumywukctsbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3frUMYwUKCTsbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
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
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
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

v4:
* Fix percpu_is_read_locked(): Due to spurious read_count increments in
  __percpu_down_read_trylock() if sem->block != 0, check that
  !sem->block (reported by Peter).
* Apply Reviewed/Acked-by.

v3: https://lkml.kernel.org/r/20220704150514.48816-1-elver@google.com
* Fix typos.
* Introduce hw_breakpoint_is_used() for the test.
* Add WARN_ON in bp_blots_histogram_add().
* Don't use raw_smp_processor_id() in test.
* Apply Acked-by/Reviewed-by given in v2 for mostly unchanged patches.


v2: https://lkml.kernel.org/r/20220628095833.2579903-1-elver@google.com
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

Marco Elver (14):
  perf/hw_breakpoint: Add KUnit test for constraints accounting
  perf/hw_breakpoint: Provide hw_breakpoint_is_used() and use in test
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
 include/linux/hw_breakpoint.h        |   4 +-
 include/linux/percpu-rwsem.h         |   6 +
 include/linux/perf_event.h           |   3 +-
 kernel/events/Makefile               |   1 +
 kernel/events/hw_breakpoint.c        | 638 ++++++++++++++++++++-------
 kernel/events/hw_breakpoint_test.c   | 333 ++++++++++++++
 kernel/locking/percpu-rwsem.c        |   6 +
 lib/Kconfig.debug                    |  10 +
 11 files changed, 885 insertions(+), 179 deletions(-)
 create mode 100644 kernel/events/hw_breakpoint_test.c

-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-1-elver%40google.com.
