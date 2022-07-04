Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVMDRSLAMGQEH5S47YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id BC799565933
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:05:57 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z19-20020a05640240d300b00437633081absf7314076edb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:05:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947157; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJUeaIdiisbxN32ebTOEwtcix2Xe88E2Lsn+rlDmfm9ape0frV7+xem2YQpCVptku8
         jWfbdpbXHJZONQhJdhkOhLm2cU5mZejjiXNLaUsjwky5jLSoLDoCz++QrL7tGVT5gF3K
         Thb1zHtQqfbw/7oyBT2hwxYmSIUdtxco30BK3We0m4N7WReZ1Kn8VDUfkBuyW595kjvz
         oen3zzhzyj4sXMtiyG7ngptSXguKL3X60GSaMgEln7qo7pyRmS3JDRnHHjUfvJhMdsMa
         Ivzl0JNE+/FAMyTyvwBR0b1WBBXUyjyWQRsqbJfV6yUVnmV1og4dJK9JrGcuigweY6Ji
         YDjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=c5kbsSn7aecw0Jug9SGkBmTVmrsDMjtiA/8/cYIPx+o=;
        b=FaChD6JMW2sd+la490nX4uL3/yjOA1NlqDuJSq0AFYSSx9s/Kl+mSB/FwcQpo/6/oB
         JTciA+3Pmi7dYva5R9wb9B5ezXOyhQnND0JgBNEp+whkGpz9tUrMEirHCwFT0mM2GOR9
         Z5kegHmdelSnuAtDDORgjAG/OZ1RA2gu1LNPTt3EvPOhFWxDfx+UwaWvSXb66nF0uj+2
         d81jcVWe87ejXr0IB1R4WErkpTkJnjSeUoC1XPq5zPhQFHg+8X3Dd9O5nezY+AZ/WbaR
         yZMx1hkNjxTX6HUEUZVj+hjj9erCiAAg9NIvW8wuaej+YWJO0G4XA/5pnjOQf1iIVqxB
         GNrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HFp/v8d2";
       spf=pass (google.com: domain of 30whdygukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30wHDYgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=c5kbsSn7aecw0Jug9SGkBmTVmrsDMjtiA/8/cYIPx+o=;
        b=KlNEJxnpNJqCXQDObf/ihqAPnm3yYBAMyTJl+SjpU0QmfBKBhZNbnclB+SqvvL9QmO
         KGE+NcNm2iLJwwTLqqitHHI890Qys2xYWgVzYu5dyjkABMnUYj71JyOhpoBK7oEkrruL
         1e2DNdfwo+mWYhmQl52bO49B9EDJYguJ1HHbYam9s+hVAXDicUhOO+8d4a5Gp1xZJHgX
         fZv+rUle4CoUacmF9sbjus3Qz9MjgESybdaJMlwd7bu+fMfxh2JwqCOoPJnqhM0P9DM5
         waYq2Fr4m8u61MmY9Q7d0+eMz6jkqgOGCivTDwhZjXDBbEZH2fT0mNSx5vIiF1mOn531
         jfUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c5kbsSn7aecw0Jug9SGkBmTVmrsDMjtiA/8/cYIPx+o=;
        b=JEQekCdYxpA4S2qJtYYZMMfnTLN/5dZ3QHa1fmtNw/kOOFWW1YW0uASr1sGQpNaJqt
         DzQI64NSM/8FykYbfV8jam11wykmsUOPNP3x2x+3//1ItkJvjT45kLS6J2mZXg3THrgj
         /GpXDJWsS9CiPXzYlgK+ulRHUDbTZNfN5rUDbkv7dZFIINWx0xSZ6ILJ7MuzaeuFWfVn
         eWvcJpDCD0+AGNFaNOjbpK//+NoLoQXDCBbClpMHwbI5ePnPKZCnRqlvqwfkfZiFs7jb
         arxB1Wv0tAVQL8VVWJxjuxe3RImu67UcWZkJFN9knBoF1kBXdBO6bKJbf9o03aN7qwa7
         mF+Q==
X-Gm-Message-State: AJIora8SWbXSDjWh3KDzOylSjmFOje5YKml5CEE13xepsMyDH3ZH0ZKv
	VC9oWYBaHUTl3XBOD9Uc9oM=
X-Google-Smtp-Source: AGRyM1vDBUYQFns3v8Z8WugF6uDrJ5NC4LTuixqH73Ud3v0CFbPtydOihBUjFz0krWPXGZ20tfcKlQ==
X-Received: by 2002:a17:907:9484:b0:726:97d7:4143 with SMTP id dm4-20020a170907948400b0072697d74143mr29358317ejc.757.1656947157308;
        Mon, 04 Jul 2022 08:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls7512072ejs.6.gmail;
 Mon, 04 Jul 2022 08:05:56 -0700 (PDT)
X-Received: by 2002:a17:907:1c08:b0:72a:8a2d:db4a with SMTP id nc8-20020a1709071c0800b0072a8a2ddb4amr18247240ejc.89.1656947156024;
        Mon, 04 Jul 2022 08:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947156; cv=none;
        d=google.com; s=arc-20160816;
        b=KDgw87lhQ81HJ6sNkzmB3Xya7JidJljMIk8Rbak5sgjhLBwkvTtFD+ge0iEDMR1kdv
         IA2qFsCSuJdV5tFzMXzWAueKME2DZ+v25IUcruO5Mw1nyAJYpf+/fASMih1KmocIvfdw
         8I9mXLx5f5CdiqCu0hlTImZWqJWui7dufhX8ygZ+YuUkKgbs4fe3Mfqp73oJGzteJX8a
         IUkPEW/BF2kEqHLeHE5m/7yZsIqdQ3Xb6k0ywMIX76KI95j2aWTFWR92OwJvspY2dFgz
         IJJnfXU3NYZOaBdBzRtNCMw2vDKEo6N7O5ts5psiIAgf6R3cuTbCASCYapOL+cWcoIVc
         ga9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=vCw+qYcLfEryg0NCqZvoZGaEOfEUqqIfSJ3H2Y/La+U=;
        b=d45IPdYmrdeIeBsd7WFbo6pJc/a1xNI894Ny50yANDq9G+YvKrGRTcjLU7JHfXhXAV
         9uShKdER+nZnt+kwqRwxn6eEC+eA4JWqqxGJI8AbBgmn3AYhDhAZeJKFtxYiVeJkU7Ne
         ijPxpGMjShLnKXX3VA9I63wS0Aj7SDxCNDtjrH6SoUI3Ogsa+VysktskmDSdOxBd2589
         yIzl4wQkLJMeQWeO6YgnKVaSslqQjrtcRNm+EjM31xjCgDGWms7usccjqap/4ugnGAAY
         pd1dj2NOv+hKXfAEbEwVvHOcwbdD4BtQxb69/eSlUSe/S++8mFbU1m/geecPy5ous+Rk
         IPfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HFp/v8d2";
       spf=pass (google.com: domain of 30whdygukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30wHDYgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id s19-20020aa7c553000000b0043a2a36df0asi122103edr.1.2022.07.04.08.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30whdygukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id h16-20020a05640250d000b00435bab1a7b4so7389429edb.10
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:05:56 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a17:906:9b86:b0:6f8:24e7:af7d with SMTP id
 dd6-20020a1709069b8600b006f824e7af7dmr29696674ejc.295.1656947155542; Mon, 04
 Jul 2022 08:05:55 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:00 +0200
Message-Id: <20220704150514.48816-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 00/14] perf/hw_breakpoint: Optimize for thousands of tasks
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
 header.i=@google.com header.s=20210112 header.b="HFp/v8d2";       spf=pass
 (google.com: domain of 30whdygukcf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30wHDYgUKCf4kr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

v3:
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-1-elver%40google.com.
