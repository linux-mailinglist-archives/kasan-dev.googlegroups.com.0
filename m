Return-Path: <kasan-dev+bncBC7OBJGL2MHBB36EUKBAMGQERMCKP5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id CB47A333A3A
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:41:52 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id t3sf3255884uaj.14
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:41:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372912; cv=pass;
        d=google.com; s=arc-20160816;
        b=LorlT40TTSBa57mY+bwHaXvWoGAkIYRw7C6T+iqInkV8IvmNEVkD4/MgwNXr55sYAh
         lfhhO8cihGnaKJjgWuwJherueCHAZK1LRqmSvQnPqbVP/wXN98AUgepynyOICZHaq/D+
         YjGWzjGCeH6LYq26vb4VijPOI044qcJmjWTPcwmTLDV1K+5lEhOpXFPcXizaWLHyFtPR
         ahfn8eXXS/6dBFtI+caPP3y0bTKu+CkDHH0+XhtN64mHynvjkQoeaQQv4oYL6vIbOm3n
         JotW9rBoo7b8aORieuGDN/5HooYP0TVv6D8ApMhBltuZW60Qbp/tuO0u74ve6Vj4u7rx
         gBeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YSgbTqC/h9BWrmqPoaEEV1NDKdSOaPb6dBb1bLSU4V0=;
        b=cSEMcpAIoWpt11Lux9blc9mjK1m0l4M4U0qNUDInAUCvGkixOc5eUxDWuRPUmKtuhn
         sw/941kAJfWYYjLpQpke0+8w0Siu718gost/EY++mWEuRVfu0vlAjJrJQvmBAnXcnsfI
         qJlKLIZSQnvqij398qvqD5YVMiwe8IEH6Ozw03Rjsx0J3LRPiimJ9uLtgH50XSNbb6WE
         ral1CNpNeDMZ/2fiHB/6wfD039d8GAcCHrtR+s36jyY2jWkXL61MLy2aD4EftYGVjcU4
         tu6JeVE0gRPPNMFMJJcVK5pYP3lnetksb2oeFqTe9q2mkFg38RXzhC8gnYloZBKLAmr+
         +SRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s8QQMW2L;
       spf=pass (google.com: domain of 3bqjiyaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3bqJIYAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YSgbTqC/h9BWrmqPoaEEV1NDKdSOaPb6dBb1bLSU4V0=;
        b=BVguZcib1oNYxWOTiByg1mhe5+p/C3Wp0853+usHmdyDXHW/x9umkgJ3giX2CgWZDP
         QqNeiYAicz72pynMBcN5kKPbX1zXTYA2sCmp4/OJS3qXgpvwwoRcoP/KBTAbM462td/K
         cIO9rFTtYLYhj2ozOBWAp25X/0rPjteUNvGr7zRNy5GbQHI1ltOZ8uyGmWBUDrk9cPkg
         U90aqy0u0nt4fElIz5BghC94nDZl4AaDZev/REmLRSHLlRCU6Lv+8TLm4NEsLNj2YCwF
         EORNRKww4E+UVVrjRMBJ4f/fQ4GY4SFsUcQlP6e90FHMPfJY8f3ct9iTnhD296WzMvZ+
         pmbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YSgbTqC/h9BWrmqPoaEEV1NDKdSOaPb6dBb1bLSU4V0=;
        b=YSNDjpPbx61vY7ov3ucKjRPfAKLRAbSx2jtUUBCp4bEntG5KUS9+vkC22GzslTp2XA
         vF282hCWtozlUcyeqHVZWf+QOD11m3hUF/AyEshfzfX3SGAmtuefHdlLChLw5JsrS9+5
         Q+kA8AfHIIPGSPruZU0nBGS7jnx6qFSZf+koLn1fxbArr2PxM7tvfDyOb//HnqAYvqsN
         b5p8CsDMv66u4AXEyX6Io3cFaM2qjUZOTwWGPkGGrjut/M6wNJCbqQSNxULRxxTSU+13
         GeAMBblmoDc1UWoGFrV4z36h4YX20l9qAkPgRMY2FfWn4bUbAPmavhD3PFjmPpBDBl+a
         JcFw==
X-Gm-Message-State: AOAM533uvFxmN0n46z9bQ4+Qediq6/hqVxeQ6RzGSEFaNnIibc4hD1Vv
	909CoaGkvhLEgDR6Cd+jUeg=
X-Google-Smtp-Source: ABdhPJw9IlrLPG2BqHBXooY5S/IcuIJx6FQggvwEOR91f5bj68Gp3P0UQGAuiOZ072Zs2m/HR1R2jw==
X-Received: by 2002:a67:7f4f:: with SMTP id a76mr1243671vsd.45.1615372911682;
        Wed, 10 Mar 2021 02:41:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:64d0:: with SMTP id j16ls121138uaq.11.gmail; Wed, 10 Mar
 2021 02:41:51 -0800 (PST)
X-Received: by 2002:ab0:32d0:: with SMTP id f16mr1205669uao.64.1615372911057;
        Wed, 10 Mar 2021 02:41:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372911; cv=none;
        d=google.com; s=arc-20160816;
        b=TTnoDtCnlvxFRX3ty0mD8tc1/gLaiWgMTRoPQERq0SqHDmNwBM9ol3o0msB7xYtT+R
         mZICTbWeJgEH+fI+Iwk60Xpd5R5l/caemkTL8EMHKjWrPNuWeEGuGVcwJJxWVPtnRk2+
         Sc2eR950cs5Inm/vEmFKwifp0mt9iaSxr7ohTR6dzQw2wIIInChr/ouBorNPkMEMLCje
         0koL4EXhrXn9wzBPZzqD8ICdlI/2XwgjZMHqsmTnW8C1NT8fG/CIGEaJnXyyItPX+9pY
         eZ03JtzgQWVw18H9yS+XUc4zAl2jzByay0sS1vxF+UhGq8QKOMWS4z9DoYUplA65AhBl
         Pnjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=CXDGXPLv4zBuXju/CY+pJKsC5gho63hQizGsKGKZIlo=;
        b=tZ8QYIRuldD9ElcCCsjkkyvnBQK+afLxtGEFfU4cGRv6eMQhhl7H2ABEAHnTqXRdwe
         vi9gtZFeLnNQIc2UhLeLGW06i+f73Jgx8RO2QEC7RCnR0rd3fIVk+IIWlOQaUi+FK9Hu
         o9KjI8N3ODxQJHLoPQ4fWI9MAYJAey0bw3H5UqkQxScYyIkM/R6wrR8TAEwSl04oDM5p
         gIu7giTuMPvyoLooanYd6Ilb99t3d7UqShWCmfZ3omD4y6zVnsovvb0wG7YCcJA4lxM4
         Fjhu9CjkH9rx3XHQEN/P5P40HRiZT1GngiuMR+ahMtsjW3hzgPdMWEmKrdhElt9CvViR
         Jkmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s8QQMW2L;
       spf=pass (google.com: domain of 3bqjiyaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3bqJIYAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id w26si998303vse.2.2021.03.10.02.41.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:41:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bqjiyaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id u15so12353731qvo.13
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:41:51 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a05:6214:2262:: with SMTP id
 gs2mr2155838qvb.32.1615372910698; Wed, 10 Mar 2021 02:41:50 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:31 +0100
Message-Id: <20210310104139.679618-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 0/8] Add support for synchronous signals on perf events
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
 header.i=@google.com header.s=20161025 header.b=s8QQMW2L;       spf=pass
 (google.com: domain of 3bqjiyaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3bqJIYAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

Examples how to use these features can be found in the two kselftests at
the end of the series. The kselftests verify and stress test the basic
functionality.

The discussion at [1] led to the changes proposed in this series. The
approach taken in patch "Add support for SIGTRAP on perf events" to use
'event_limit' to trigger the signal was kindly suggested by Peter
Zijlstra in [2].

[1] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpocX2jwVAbZD=-XQ@mail.gmail.com/
[2] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/ 

Motivation and example uses:

1. 	Our immediate motivation is low-overhead sampling-based race
	detection for user space [3]. By using perf_event_open() at
	process initialization, we can create hardware
	breakpoint/watchpoint events that are propagated automatically
	to all threads in a process. As far as we are aware, today no
	existing kernel facility (such as ptrace) allows us to set up
	process-wide watchpoints with minimal overheads (that are
	comparable to mprotect() of whole pages).

	[3] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf 

2.	Other low-overhead error detectors that rely on detecting
	accesses to certain memory locations or code, process-wide and
	also only in a specific set of subtasks or threads.

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

---
v2:
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

v1: https://lkml.kernel.org/r/20210223143426.2412737-1-elver@google.com

Marco Elver (8):
  perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
  perf/core: Support only inheriting events if cloned with CLONE_THREAD
  perf/core: Add support for event removal on exec
  signal: Introduce TRAP_PERF si_code and si_perf to siginfo
  perf/core: Add support for SIGTRAP on perf events
  perf/core: Add breakpoint information to siginfo on SIGTRAP
  selftests/perf: Add kselftest for process-wide sigtrap handling
  selftests/perf: Add kselftest for remove_on_exec

 arch/m68k/kernel/signal.c                     |   3 +
 arch/x86/kernel/signal_compat.c               |   5 +-
 fs/signalfd.c                                 |   4 +
 include/linux/compat.h                        |   2 +
 include/linux/perf_event.h                    |   5 +-
 include/linux/signal.h                        |   1 +
 include/uapi/asm-generic/siginfo.h            |   6 +-
 include/uapi/linux/perf_event.h               |   5 +-
 include/uapi/linux/signalfd.h                 |   4 +-
 kernel/events/core.c                          | 130 ++++++++-
 kernel/fork.c                                 |   2 +-
 kernel/signal.c                               |  11 +
 .../testing/selftests/perf_events/.gitignore  |   3 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 .../selftests/perf_events/remove_on_exec.c    | 256 ++++++++++++++++++
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 202 ++++++++++++++
 18 files changed, 632 insertions(+), 15 deletions(-)
 create mode 100644 tools/testing/selftests/perf_events/.gitignore
 create mode 100644 tools/testing/selftests/perf_events/Makefile
 create mode 100644 tools/testing/selftests/perf_events/config
 create mode 100644 tools/testing/selftests/perf_events/remove_on_exec.c
 create mode 100644 tools/testing/selftests/perf_events/settings
 create mode 100644 tools/testing/selftests/perf_events/sigtrap_threads.c

-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-1-elver%40google.com.
