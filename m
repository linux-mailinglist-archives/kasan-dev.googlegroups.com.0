Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPVZXOBQMGQEY7Z3XVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 41DA33580B3
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:48 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id h18sf779467oot.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878207; cv=pass;
        d=google.com; s=arc-20160816;
        b=fB33V5S+ADtQHhQvfs+kjQ1ejByqNFel7HsVVCenWkkgGLpw++kNMyNdHR1L9+ZLf5
         aIB3rMj4zSYEfTeepqPjwZc0tlpF6Dy7xZByrW8PZTwgvpX/5mZey8UUzNFH9NWrxJAh
         /oDzIGzkOYq2NOu8KkyvFomCPUY76u9ZKYsW8OWU20sJGM15vlK2E9L4APCQvEXBkwq4
         Nwl+hOcraMGZbllcb9mfxbHZqIsv4HWrbnhwmFE2M4jsNGEwmwRYYhP+Db0/w8SLs9V0
         qRIfnmAo7wk1p1u09U5hO5HPW2seltfTFLBg3sCk6vWPpebwDMh2+VBWQy/2lSut2jkn
         6lPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=tX7O9cHQlbYtaBoWTuOb4X6W0UHeEjn0WDAXKtqDoyc=;
        b=XCgY/af0oYkIH+aFcvT0aDbo0tZoc2JGolY8QInMmcsADmoybYCthKR4CHveeJceag
         cl3DKvqxc2s5a0WVapMY6WypBfy8hEhU6dpoTc67KZS13NKO90gTUmk2qPlnwXd1H80Y
         rAnU6hZzqpgFw2/LExf9dAHUdVhpDiQphQ71IDQdzzLlMk7XimHGqX+buUoE6IdKkPTC
         kpp8Q+NRdFp3P+F9bOVxhqqgioG+uYOaPIBCzEpGrS7e7E1EOoUFqORb33fHrQq02BmM
         e52cJo5TFL/otpECh991yOjS4IoFugIIC+00GRJY2HvEO0Cjnp1HGKrzHGW0R7VMAlQN
         7YrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CE/uDe25";
       spf=pass (google.com: domain of 3vdxuyaukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3vdxuYAUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tX7O9cHQlbYtaBoWTuOb4X6W0UHeEjn0WDAXKtqDoyc=;
        b=f0eVJoUHWk7wgJO69fs8se6RAHZDXYCWhmC6F4NRuBo9fY8WwGosz7x96X9iU4Qzu4
         4nsBt2F4tekcyjMSmItKhxfilf/d6c0y4aygeTLJVRwHYdKm93dxnYEhyKhL35zNX6Nn
         BAg5Hc/1rbEHaUVGFbwqr6/yurljeJapsWquVt2II8JTjmMJ+RBC4BWk2aaIwLGv85fb
         Sjo0a2EhoQsHoJCKV6n155Hf8GyV5hVoVYVcnyz3AIpOWBtEibfMvMPFSb/VLHY+yYwW
         9yoeplPCYFMNf43sHfoYqK4dQ7z7pFzsxcxZ3RKNjjtnC4Zp0liyG87EgZKDl8I1jN3v
         aQGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tX7O9cHQlbYtaBoWTuOb4X6W0UHeEjn0WDAXKtqDoyc=;
        b=L9kyRsTSjOYo1e6S2WVey+KfnYQlfcZ5Ho20Hn40bfwf/YrGXnEma6AXugNqNXreeS
         vNg3RppYswB7vZx4pLBS2gCegNqVV4GrVYsrQ7Hn1QAVI5i1/F8YO5DwdrQ4qhTJVYDm
         jv01c8Rtov7Ci/BmJIcWDH6QmjvOJW/8hPzjIOZK6ienZtI06D++YAmslM0kJv4CVldA
         MGDmW0vs9TlvRWBOOsLgYCWNVo3ayCVaeWV57lwzuxpY7XmWPdq+7/IycIYnrpVWa/RR
         X96feNmfIXfEaibXUdt2C21Qu30a4Xal5NRKVUArBYc80kiMgJzsGe5UYMow0kSQDh3w
         jryg==
X-Gm-Message-State: AOAM533TYvhxin60kuaztzSHsEj7qwV9/D2Cciht6736iiNm+/Qmtc7X
	tEeBXPglRzH1v78tn5+27TE=
X-Google-Smtp-Source: ABdhPJyShrnxESC6mO3F5RGhcE9pEjdHszbRVFiopOEn2a5dlOpD2w8ImmG7JjF8tEh5Pzj319JHLA==
X-Received: by 2002:a05:6830:120b:: with SMTP id r11mr6719180otp.82.1617878206900;
        Thu, 08 Apr 2021 03:36:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7456:: with SMTP id p22ls1250638otk.11.gmail; Thu, 08
 Apr 2021 03:36:46 -0700 (PDT)
X-Received: by 2002:a9d:7a42:: with SMTP id z2mr7069254otm.366.1617878206497;
        Thu, 08 Apr 2021 03:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878206; cv=none;
        d=google.com; s=arc-20160816;
        b=T73X8od6piVNn6rLa218QFOlA1pl4XKUq1povbFNuFx5qxs5oYWMTr+R5Kp0X6YITN
         uqCoA5ClhZzUMhMHYFcU4Xr2pq6rYfoAoZXMe0N1adY2rv6EqROX21MG5h+eggZlB38w
         jro7a8Lou1yLoHkgJxzKp3KVPqDudM4Ivjr8mo32t05dAgeuoL6fhJE8XscNbWnwEMwj
         zFnhdI8REtAx3SN3Uoy1VVIyufuirjcOjAwZx1dYzJOCFi0QoApJt53FYCiILfsAO+fu
         SkUvevsWrM0XanDvhRNhg0twsw/FXqJn+YM256b1UWLTOK1D9IcVxiXKa5KcX63mHd9m
         LKjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EzmzmhSLYOYTzia53fwYPMbr67HMT97fl1vfB43xxy0=;
        b=A+2BDbche/IR/xGGcxOSVtQdy8TeANQu6o42ypgCRhvr2JWAWjotumDM/+O2aWoi0N
         xY2+DlVdqKTJPZGYqAg79r4dZD1vF0R/pj3Yc0yQ4f85E2T2T07rG8LqpqxDcxRMNbNR
         BEe+c157xCcMFuKvsHLU4KFAWWAxgHwhb4v3H+DD/JCPXsjuKR2Ho8Dk7dfqeB9Il5vp
         96V8mGzOW9dBKIliV5792ONcq7OjLbCMJE7qJQ7qrmy8e8zTPmZcT18Vye74R0WEKH94
         KAb/Cy7WRO04CAUgQQh0nPcvEBz+Xv1uJpH2da3zAJF+cptetcdd8MZ8wbt5cP4BGX4j
         l6sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CE/uDe25";
       spf=pass (google.com: domain of 3vdxuyaukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3vdxuYAUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h5si2612890otk.1.2021.04.08.03.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vdxuyaukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c1so991462qke.8
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:46 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a0c:b348:: with SMTP id a8mr7834915qvf.7.1617878205926;
 Thu, 08 Apr 2021 03:36:45 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:35:55 +0200
Message-Id: <20210408103605.1676875-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 00/10] Add support for synchronous signals on perf events
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="CE/uDe25";       spf=pass
 (google.com: domain of 3vdxuyaukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3vdxuYAUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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
v4:
* Fix for parent and child racing to exit in sync_child_event().
* Fix race between irq_work running and task's sighand being released by
  release_task().
* Generalize setting si_perf and si_addr independent of event type;
  introduces perf_event_attr::sig_data, which can be set by user space
  to be propagated to si_perf.
* Warning in perf_sigtrap() if ctx->task and current mismatch; we expect
  this on architectures that do not properly implement
  arch_irq_work_raise().
* Require events that want sigtrap to be associated with a task.
* Dropped "perf: Add breakpoint information to siginfo on SIGTRAP"
  in favor of more generic solution (perf_event_attr::sig_data).

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

Marco Elver (9):
  perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
  perf: Support only inheriting events if cloned with CLONE_THREAD
  perf: Add support for event removal on exec
  signal: Introduce TRAP_PERF si_code and si_perf to siginfo
  perf: Add support for SIGTRAP on perf events
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
 include/linux/perf_event.h                    |   9 +-
 include/linux/signal.h                        |   1 +
 include/uapi/asm-generic/siginfo.h            |   6 +-
 include/uapi/linux/perf_event.h               |  12 +-
 include/uapi/linux/signalfd.h                 |   4 +-
 kernel/events/core.c                          | 302 +++++++++++++-----
 kernel/fork.c                                 |   2 +-
 kernel/signal.c                               |  11 +
 tools/include/uapi/linux/perf_event.h         |  12 +-
 tools/perf/tests/Build                        |   1 +
 tools/perf/tests/builtin-test.c               |   5 +
 tools/perf/tests/sigtrap.c                    | 150 +++++++++
 tools/perf/tests/tests.h                      |   1 +
 .../testing/selftests/perf_events/.gitignore  |   3 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 .../selftests/perf_events/remove_on_exec.c    | 260 +++++++++++++++
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 210 ++++++++++++
 23 files changed, 924 insertions(+), 87 deletions(-)
 create mode 100644 tools/perf/tests/sigtrap.c
 create mode 100644 tools/testing/selftests/perf_events/.gitignore
 create mode 100644 tools/testing/selftests/perf_events/Makefile
 create mode 100644 tools/testing/selftests/perf_events/config
 create mode 100644 tools/testing/selftests/perf_events/remove_on_exec.c
 create mode 100644 tools/testing/selftests/perf_events/settings
 create mode 100644 tools/testing/selftests/perf_events/sigtrap_threads.c

-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-1-elver%40google.com.
