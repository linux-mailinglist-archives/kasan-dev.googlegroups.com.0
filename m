Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOD5SBAMGQEBUCG4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D4E34770C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:22 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id u12sf1351898pgr.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585121; cv=pass;
        d=google.com; s=arc-20160816;
        b=OZac3mu06UQ2L6kYlqf3VNWbkRVyxSXJkqp5B48jknujpiSHyP++dSdE1AuoMeoM5V
         rLV7aR4ERdt1ecOefFT+nhwaCKtTWoK/OTPFwbbQuH4QsJyJINMriWDpjFVF0xooZ2jq
         aftzIFj3UdmWhFbZ5AGHRCtFnZP8crv9ha6Yq4kInnGcgr8uvdzVzhoRut7co6HOSoJN
         klQTm4BM1HAZe6FfA6zfuBIl/UtJmWm/21TGH1WSow8XyCB5Yzw+1UzPDO0KS0lE42sm
         G/Q9pNhnYp3JszjeD1L/cfejMrw4epb3OqhUFVTQu/Qmpru+tML/ZslkCC/qf/60JTf8
         M+fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=TtmFdQ1lxeKO2JrhI7YjgqMQOXVUU0NtYUJN3FzzWHE=;
        b=FKGxoWjzIx/OkSioZziAzcca1Lo6OVYLfPAn9hVV+EAXIOa63ngfdyPPnTOoi7VhS5
         zgvOTWdZlHpO2U+uBvOoV/o+z2KHcKt8wiZbH/XRiFHYvXFUQ13l7YEARcJB1WZ51LGK
         +Xd8Sh+p7m2Z66qzfSXVxuLelPL0tl3AF1RZtRRlsUDR4K+vLBEfOy9jNETMthGD86qQ
         hMtXBTBeFglq9i5SfRSrh64lFgify0/4fSiD1lOwLKsdV9FGIjKOn9Of8DkD2J3FDGHv
         7hSiCNdzjEYcfcEwauHiTdYV4SRNLpgky4FD4glmIghhAWJ8mxFcSiTGvZfmVJLjIvU6
         9wJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pwcY4wDs;
       spf=pass (google.com: domain of 3nyfbyaukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3nyFbYAUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TtmFdQ1lxeKO2JrhI7YjgqMQOXVUU0NtYUJN3FzzWHE=;
        b=kmxHdarP8o+ahtzKndOp6U/06GJ0/Wtm9JHMkEcAI6qSPN0NDyE/NXHHVGPe5eMx2h
         RPAawqWl4Rw1rNQqUquk8QBGD6Lnl3DL3m61abkY7784kRgtlqsjsJgV25kSmzu85WB4
         XP3XoU1YxNVc4BmdonK2pTx1Z0qPn4vFEugd2zWrmRHPYMYMQoutgDCnj2S/M6FKaoHD
         piAjnnslv2x/DpR1/jV1N6KxslfzLT+z4Q3dlEUNHRH9hgU2OnZ9sAcNhPjaUKbL9Sl6
         QiM9uzENqHeyFSZhSk7PVrVHPzIf0OdeCPxF99G3cf5xtt1ipyQIFF8WTFjjcM766RfJ
         lsoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TtmFdQ1lxeKO2JrhI7YjgqMQOXVUU0NtYUJN3FzzWHE=;
        b=sNIMhFXv2B26mVJKqQePYnaK267Gw4i0StGzfegnWeW8I/9MH6GRy6moXTFu0FUnnc
         yghTgk+2+K4lG+0CmfMGFdVW45U9m+gPgYmJ37CRK7ywSQtFn8s5AlByldBrET2C05lt
         wjA9lWbzUAdEa03lQ6ojJShE8qDuoeS1Hxhd5S7cAprJE6FP4LqVAOMvp6h4lz0Ak1C2
         Lvqjqhzk1Y77VETCFfHN9/mL5n4APp1VM8Oo0EcjHWSu/I6ufsNCOwQY5QeFu1+JYtXv
         tHAErQwLbX55PgJXoAmUN1zI79064kJT2gwB08w8FvCGcFNO+3X+WXNgZrHNkDI0Nhef
         xxzQ==
X-Gm-Message-State: AOAM530h/Y98n1ASm1mSRKKRw75nLB3P0U+7fUrsgL/e1/PM7re7lxrV
	JWI3xyEXlJFG4dgFl/EW1kc=
X-Google-Smtp-Source: ABdhPJwXuulAJ/9ZM8I0fMB3KopELMUtliyY5pqNS3RznpwypNayL7Ul2XurXjTGFPNOE2Sa4oZpiw==
X-Received: by 2002:a62:1b88:0:b029:1fb:d3d0:343a with SMTP id b130-20020a621b880000b02901fbd3d0343amr2592863pfb.76.1616585121200;
        Wed, 24 Mar 2021 04:25:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40a:: with SMTP id k10ls1124568plk.2.gmail; Wed, 24
 Mar 2021 04:25:20 -0700 (PDT)
X-Received: by 2002:a17:902:e5c8:b029:e4:c22d:4da6 with SMTP id u8-20020a170902e5c8b02900e4c22d4da6mr3248830plf.10.1616585120496;
        Wed, 24 Mar 2021 04:25:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585120; cv=none;
        d=google.com; s=arc-20160816;
        b=cG9QTktdEc8SyvE7+dzhNnBSrreKFs0uJGZeVpN5fpTl42Y6rZPmfzoBDkIkAnGNzI
         RSFczmqjQ7W+YO5arWfd3SttX+sgENyvy+oTxUtToeBLX4hi9iEPVBrTk2MXhd4n579Y
         gcp02/mxY2oHPpXODRmUqCCpd+xWTS6RFLWamiUvZW1eTuZyiBMOLzoOoUor9zih6AY6
         8b5SSBOVpl+fWunZKkm+uMPcgNVw622iC2u++bkRLpSgDko3IH2ENpsH+8ztgbn/dAKW
         8tdkQIdv2f7FfX/wcHKDhZCyXEJrR403GZZRLCV5+mjqxbpcFrchHrbZIyVk+En2BmCk
         ymtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DE1DVxC3WyxIHHd+lUpARd+jKa2DD/enh2sGUuOmG0E=;
        b=W0oLMnK+2aE/8GmM8s8bb7pVewbXYdU1gwASgSsQ7mA7ANrA5bMRzvEHs+w0uigKSU
         9zINu92eAfzZmnxuMvxrK7QYqk2HD2DO78GNxRU590AmO6qH+GCNX1/l/eC93v2FWMsz
         8Rm70I1tfUh7V4U4ayPFEZoXYVmmYE1cjfhA93oMzCfB2cOBSHaNIonhhvTvWAjQkDVE
         nU2Bh/mnomKHCyBMUU/c34dn2T5cC3pzDXkBITj4u6/oF8xFYavH0suk41oWaxGVw42R
         6ynJCZWjBaV8yv+buPyx0537f/voBngBkk4EVJnLVhtmwNf32Ghc8wDDCeFvB656tEL6
         DhqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pwcY4wDs;
       spf=pass (google.com: domain of 3nyfbyaukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3nyFbYAUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id k21si114240pfa.5.2021.03.24.04.25.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nyfbyaukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id k4so1129651qvf.8
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:ad4:4431:: with SMTP id e17mr2503115qvt.37.1616585119594;
 Wed, 24 Mar 2021 04:25:19 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:52 +0100
Message-Id: <20210324112503.623833-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 00/11] Add support for synchronous signals on perf events
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pwcY4wDs;       spf=pass
 (google.com: domain of 3nyfbyaukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3nyFbYAUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

The perf subsystem today unifies various tracing and monitoring
features, from both software and hardware. One benefit of the perf
subsystem is automatically inheriting events to child tasks, which
enables process-wide events monitoring with low overheads. By default
perf events are non-intrusive, not affecting behaviour of the tasks
being monitored.

For certain use-cases, however, it makes sense to leverage the
generality of the perf events subsystem and optionally allow the tasks
being monitored to receive signals on events they are interested in.
This patch series adds the option to synchronously signal user space on
events.

To better support process-wide synchronous self-monitoring, without
events propagating to children that do not share the current process's
shared environment, two pre-requisite patches are added to optionally
restrict inheritance to CLONE_THREAD, and remove events on exec (without
affecting the parent).

Examples how to use these features can be found in the tests added at
the end of the series. In addition to the tests added, the series has
also been subjected to syzkaller fuzzing (focus on 'kernel/events/'
coverage).

Motivation and Example Uses
---------------------------

1. 	Our immediate motivation is low-overhead sampling-based race
	detection for user space [1]. By using perf_event_open() at
	process initialization, we can create hardware
	breakpoint/watchpoint events that are propagated automatically
	to all threads in a process. As far as we are aware, today no
	existing kernel facility (such as ptrace) allows us to set up
	process-wide watchpoints with minimal overheads (that are
	comparable to mprotect() of whole pages).

2.	Other low-overhead error detectors that rely on detecting
	accesses to certain memory locations or code, process-wide and
	also only in a specific set of subtasks or threads.

[1] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf

Other ideas for use-cases we found interesting, but should only
illustrate the range of potential to further motivate the utility (we're
sure there are more):

3.	Code hot patching without full stop-the-world. Specifically, by
	setting a code breakpoint to entry to the patched routine, then
	send signals to threads and check that they are not in the
	routine, but without stopping them further. If any of the
	threads will enter the routine, it will receive SIGTRAP and
	pause.

4.	Safepoints without mprotect(). Some Java implementations use
	"load from a known memory location" as a safepoint. When threads
	need to be stopped, the page containing the location is
	mprotect()ed and threads get a signal. This could be replaced with
	a watchpoint, which does not require a whole page nor DTLB
	shootdowns.

5.	Threads receiving signals on performance events to
	throttle/unthrottle themselves.

6.	Tracking data flow globally.

Changelog
---------

v3:
* Add patch "perf: Rework perf_event_exit_event()" to beginning of
  series, courtesy of Peter Zijlstra.
* Rework "perf: Add support for event removal on exec" based on
  the added "perf: Rework perf_event_exit_event()".
* Fix kselftests to work with more recent libc, due to the way it forces
  using the kernel's own siginfo_t.
* Add basic perf-tool built-in test.

v2/RFC: https://lkml.kernel.org/r/20210310104139.679618-1-elver@google.com
* Patch "Support only inheriting events if cloned with CLONE_THREAD"
  added to series.
* Patch "Add support for event removal on exec" added to series.
* Patch "Add kselftest for process-wide sigtrap handling" added to
  series.
* Patch "Add kselftest for remove_on_exec" added to series.
* Implicitly restrict inheriting events if sigtrap, but the child was
  cloned with CLONE_CLEAR_SIGHAND, because it is not generally safe if
  the child cleared all signal handlers to continue sending SIGTRAP.
* Various minor fixes (see details in patches).

v1/RFC: https://lkml.kernel.org/r/20210223143426.2412737-1-elver@google.com

Pre-series: The discussion at [2] led to the changes in this series. The
approach taken in "Add support for SIGTRAP on perf events" to trigger
the signal was suggested by Peter Zijlstra in [3].

[2] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpocX2jwVAbZD=-XQ@mail.gmail.com/

[3] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/


Marco Elver (10):
  perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
  perf: Support only inheriting events if cloned with CLONE_THREAD
  perf: Add support for event removal on exec
  signal: Introduce TRAP_PERF si_code and si_perf to siginfo
  perf: Add support for SIGTRAP on perf events
  perf: Add breakpoint information to siginfo on SIGTRAP
  selftests/perf_events: Add kselftest for process-wide sigtrap handling
  selftests/perf_events: Add kselftest for remove_on_exec
  tools headers uapi: Sync tools/include/uapi/linux/perf_event.h
  perf test: Add basic stress test for sigtrap handling

Peter Zijlstra (1):
  perf: Rework perf_event_exit_event()

 arch/m68k/kernel/signal.c                     |   3 +
 arch/x86/kernel/signal_compat.c               |   5 +-
 fs/signalfd.c                                 |   4 +
 include/linux/compat.h                        |   2 +
 include/linux/perf_event.h                    |   6 +-
 include/linux/signal.h                        |   1 +
 include/uapi/asm-generic/siginfo.h            |   6 +-
 include/uapi/linux/perf_event.h               |   5 +-
 include/uapi/linux/signalfd.h                 |   4 +-
 kernel/events/core.c                          | 297 +++++++++++++-----
 kernel/fork.c                                 |   2 +-
 kernel/signal.c                               |  11 +
 tools/include/uapi/linux/perf_event.h         |   5 +-
 tools/perf/tests/Build                        |   1 +
 tools/perf/tests/builtin-test.c               |   5 +
 tools/perf/tests/sigtrap.c                    | 148 +++++++++
 tools/perf/tests/tests.h                      |   1 +
 .../testing/selftests/perf_events/.gitignore  |   3 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 .../selftests/perf_events/remove_on_exec.c    | 260 +++++++++++++++
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 206 ++++++++++++
 23 files changed, 896 insertions(+), 87 deletions(-)
 create mode 100644 tools/perf/tests/sigtrap.c
 create mode 100644 tools/testing/selftests/perf_events/.gitignore
 create mode 100644 tools/testing/selftests/perf_events/Makefile
 create mode 100644 tools/testing/selftests/perf_events/config
 create mode 100644 tools/testing/selftests/perf_events/remove_on_exec.c
 create mode 100644 tools/testing/selftests/perf_events/settings
 create mode 100644 tools/testing/selftests/perf_events/sigtrap_threads.c

-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-1-elver%40google.com.
