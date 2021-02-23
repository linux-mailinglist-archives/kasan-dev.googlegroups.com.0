Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBNF2SAQMGQEZJ23WPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0185C322C69
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:34:47 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id h10sf8849336ooj.11
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090886; cv=pass;
        d=google.com; s=arc-20160816;
        b=OOLjMzKk/LhrUVnJQ3IdYaP6btnIk5f8I7CvM7xB3pRIlOPxxczbxSPjaf0cjbr1Bx
         mcAuVWlwxRzwK0ryT3kNZsBj3QEtol2sylCPDPXArTU4/AbFBKWtpjTH5/2LNbqTbwwg
         Q0casdwcN+mmtybct217y8zsgEF42Nm9k1RjoycChxhtBAU0yQIYZQ9OCyGjMJf0zwPb
         qPtpWgpi/X5Ry9eys5cnTLXzD60hA9MWqjkWxOxT0VPXq3CHQ4648KxQvOeYmbQbTBfH
         HafFp2KBVuTKfdTH2aX3QYSArAeCSrK6GTaWvGVoEqL8/u3vXT+SzuuTzv5Pm+MlasC6
         Yx3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=3kByT1dcLAmkrC8SIEfw1zawZC8NWE0JwEfW51CfYCE=;
        b=vHDY3nSj2D7whjzh47y3+FeQjTQlxpkTH3Y2KgWG2TzaXDsRgIXnDYagmK70AODLQx
         zcffmWbCxIF2Jaq+kdcdcTvEy5VaYsvrrpb2WprqEO11YRl4ZJvWY7UGfPFayXVyQtuj
         1TZNaXvbvkIH0Be1vdJZruDbsiqMdK4H3/EewHVFUjhP7jbu2563jQXV8VUl2vLToVfp
         RXEV/tu52M9mOytbc4wVlmKOZWhmfUggX+uzmPje4pHVbGzgenv+6esc9jbdLPeJyD81
         fdxmoRPQkS5j1PHWIH3nECSaw2Q8/d58bzY+hjcoQJdeB3exwv6UxD/d/EvvDf9LJFWf
         8jQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PJnNVGeD;
       spf=pass (google.com: domain of 3hbi1yaukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3hBI1YAUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3kByT1dcLAmkrC8SIEfw1zawZC8NWE0JwEfW51CfYCE=;
        b=U9BrGQpnqZbS6obfDvRSBtNlFqczIxtDNzsGCYJYszdFUI79ZKRhwoWQQRzpy26MqY
         GtF27iZPiyK++XLuVtfA9IXGvDXW23rI8aSX/DAn545K88iccXKllqFuPEXD5vRGYlBG
         D/DcR8NccVX+eyIC6+HJ5+a3CECGAv/nq6zPd54Bxmh8Fesyplfi+IcyyQnpV/t20gBb
         AnQZ2h3ctyCUN61yr/JuWd22YwN675uQP1yypQ//lk0DBTIvzgxHPcSmPEwYWM0ut9qM
         IQ8qrWwXDCqa+ecnCbTGGuBkBA3roKw7qiVbxVuxO1VT10E7zyI1a7T7ZotaUWQRTXTT
         TOBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3kByT1dcLAmkrC8SIEfw1zawZC8NWE0JwEfW51CfYCE=;
        b=skzc9Ag3S5+o0zcphmXGblEsgliBVnTbMeDZUypC9jircEywDt6BLGwyyb3Xw3Zaa5
         UpgJ0DzQ1yaZ9/d6zuN+KM1tw8gEO3jdvQQam3EYahq9G9bhOQNvTzuta5fTHBxXE3Fe
         G5Mf2csZg/FM2ms58V8QGFvEYoPHztVSvxPuvcmK5Y3rjyHebgjFQ31OU0a2dSZ0nveA
         syp6zZkm84Xw7nwqrzbJZu25vaXIf5qg1skYxoV6X5Rek1KCOdzWDkW44ISmLGyLR5gI
         kWPcbW3eozLZvJGtnrbcWHsDtTsPlORHS8UXALtT6USztwe8hduIUtc6A5+h1UiIa8oK
         xRZQ==
X-Gm-Message-State: AOAM530ovldG6Qg92hODYHoxwdJX3PI6lHYnKKdSrYzkckjTyfGZsnke
	Pa5GPq57NkAcPKNyT68C4OU=
X-Google-Smtp-Source: ABdhPJwNq9LXoD6H8KPqnMKxcIjM0Lk1GxDMsPSRhl4zuydMyEwcPDOxGV4iH0QdXK2FU9zi4ow9yQ==
X-Received: by 2002:a4a:e9a6:: with SMTP id t6mr18563027ood.74.1614090886010;
        Tue, 23 Feb 2021 06:34:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf52:: with SMTP id f79ls1542935oig.1.gmail; Tue, 23 Feb
 2021 06:34:45 -0800 (PST)
X-Received: by 2002:a05:6808:bc6:: with SMTP id o6mr17174319oik.76.1614090885447;
        Tue, 23 Feb 2021 06:34:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090885; cv=none;
        d=google.com; s=arc-20160816;
        b=XNar/1wjNLZrdP8cBZ7BZYXWYBPRsqTYZpI5FuNLe8OeP3c/CYwATFoySYVhABvxwk
         IIpwEfWKXxuL6dQ9+UtUiRpLQ745TY57sZj+ZSZZM0bRZ/Nl7goG1i4bCj+Rebwa/67j
         A6SPz698USf6cwOr48N2JYJ9cyaIOYMmJ7JExAkPYiJPwueLOjGQdGVsZjORdGhmV8wx
         9duoaASgN4amHxkkaFG8Zq3sHNG4gpEtOZuBk4uEUcZNkG4+b83WNtYFoKUvzuBMsAab
         pdoVbvanGCEVHmmahPqUDWQsmxCy4zm8aFiS/JvnBFb6X88zouWCoR9JPUQmVPbs/XZT
         gLwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Q8hQJDMeUJlqSjrNYnPafLaJX5CJRNsJS+XYHF26pcU=;
        b=dBR/R2QsYveLTis/C4j+Dk/V9mJkIxWmeN+/12BTHIfYmxawrvns2812gxnRccbHnZ
         Bu47f3smFRTVa2gWk6F5f3M59lW7T3WpVIDeglnLM2dYaJ6/Po/REhRY+xz+G1oh3hmF
         QImzGjxrXqCqzceL4gXGT3QNvAi8u++EuN0uI6SPCx3ZBqGWzde/xYN1EGC+cr5TG22A
         s4f9nL4sY+XrcV/qz3yMLb23MsVEALOy0K91oMSTv3liPTTm3Ih0Z+ass2TKzirPRcGH
         cYR3lGF/zO2j6eevZ0/6TpoLWhFIZ5eSnsO6bWW/tmBzG+81WLXsckYeC5GNkuFXDHKk
         klcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PJnNVGeD;
       spf=pass (google.com: domain of 3hbi1yaukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3hBI1YAUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id x35si603018otr.1.2021.02.23.06.34.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:34:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hbi1yaukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t5so10139717qti.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:34:45 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:a0c:a8cf:: with SMTP id h15mr25576657qvc.20.1614090884790;
 Tue, 23 Feb 2021 06:34:44 -0800 (PST)
Date: Tue, 23 Feb 2021 15:34:22 +0100
Message-Id: <20210223143426.2412737-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH RFC 0/4] Add support for synchronous signals on perf events
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-m68k@lists.linux-m68k.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PJnNVGeD;       spf=pass
 (google.com: domain of 3hbi1yaukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3hBI1YAUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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

The discussion at [1] led to the changes proposed in this series. The
approach taken in patch 3/4 to use 'event_limit' to trigger the signal
was kindly suggested by Peter Zijlstra in [2].

[1] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpocX2jwVAbZD=-XQ@mail.gmail.com/
[2] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/ 

Motivation and example uses:

1. 	Our immediate motivation is low-overhead sampling-based race
	detection for user-space [3]. By using perf_event_open() at
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

Other example use-cases we found potentially interesting:

3.	Code hot patching without full stop-the-world. Specifically, by
	setting a code breakpoint to entry to the patched routine, then
	send signals to threads and check that they are not in the
	routine, but without stopping them further. If any of the
	threads will enter the routine, it will receive SIGTRAP and
	pause.

4. 	Safepoints without mprotect(). Some Java implementations use
	"load from a known memory location" as a safepoint. When threads
	need to be stopped, the page containing the location is
	mprotect()ed and threads get a signal. This can be replaced with
	a watchpoint, which does not require a whole page nor DTLB
	shootdowns.

5.	Tracking data flow globally.

6.	Threads receiving signals on performance events to
	throttle/unthrottle themselves.


Marco Elver (4):
  perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
  signal: Introduce TRAP_PERF si_code and si_perf to siginfo
  perf/core: Add support for SIGTRAP on perf events
  perf/core: Add breakpoint information to siginfo on SIGTRAP

 arch/m68k/kernel/signal.c          |  3 ++
 arch/x86/kernel/signal_compat.c    |  5 ++-
 fs/signalfd.c                      |  4 +++
 include/linux/compat.h             |  2 ++
 include/linux/signal.h             |  1 +
 include/uapi/asm-generic/siginfo.h |  6 +++-
 include/uapi/linux/perf_event.h    |  3 +-
 include/uapi/linux/signalfd.h      |  4 ++-
 kernel/events/core.c               | 54 +++++++++++++++++++++++++++++-
 kernel/signal.c                    | 11 ++++++
 10 files changed, 88 insertions(+), 5 deletions(-)

-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223143426.2412737-1-elver%40google.com.
