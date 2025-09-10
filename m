Return-Path: <kasan-dev+bncBD53XBUFWQDBB6UWQTDAMGQE2NILTAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CD9DEB50D1B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:24:11 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-401eba8efecsf4812935ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:24:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481850; cv=pass;
        d=google.com; s=arc-20240605;
        b=l1vCYjSE+DAQTibPX4PC944wmnbRBqj/d1cO8lRpTLnRC/lbOJs7WVJWnqy+eRyrow
         VUPi8+UgYIXFw1Frxe3SIjzsQMeXwvCX6hbvV8uteK9B3RwzzqkhZ8/98vxfrKl1S9js
         SOUAUbShXqwSkKjjjiXqjSQQSPeruQ5tByOlbm9YEoOxvDcf387ByPnHCyAWE5Rar3AA
         oP7+rkS9ZmScpIBRSFyTi1UAwqoZ5qJ9MSAnI4Nh8Ilrasq3VfA/bjMOwbchlQCaOvIJ
         ThSWayd6QwwBQaEl+GZIsNeDCUDSYRrvm7w5vRvyzKe8dTwGNs16sqBV+s8NzC2nSWdO
         Y/kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=rRoPn+JSPnq/N8b0n0aoT3NBEFjE2QHpMMdkB0MnauQ=;
        fh=2DftfQCimJ9d1lFq4Jxs4ztSvGugump0VNEKThC/Y5E=;
        b=Cs76ADt9E1BidlnVTrtTDbOtEdgV6zW1O2jHvNBzq4/NFUmtMJr6JEv6VN2D/pxFHW
         q3SpfYHX+E3E17kAst+ROXObtOtlkw4KzJ9anS0iR3FoSdO/Uoh9o9kHfBTqcu0dANeI
         qKUGgmZ6B0VmkEccGmJm13b7ZLLy2QxX0zv6uqARE/Dj+OI+p7a5dpvRPD0E8+oAwy1p
         dP80TeXbtBSgOmkXffHZek/QQPAiC3K//n67nVSC6XLw7iCNM94Isfqt0eM+t/I54b3s
         4kTy7UULUtSSRbcE+6Nm0q0rsL5MmTO3SfCLQ+hxQ2gYTWWJvjBIuRO0cIs2xGvwpdod
         h4PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=G1NP4nYi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481850; x=1758086650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rRoPn+JSPnq/N8b0n0aoT3NBEFjE2QHpMMdkB0MnauQ=;
        b=xqO++pRZd6ytMZhhym+517DI3FLm/6pCWkjb8ByJ32g10CoQy6ngDyVLP3N4Dy0/Eu
         ePjr20bKD9ads/dSp43Twqg0LBhJOmP3fH1KAR6vKJFcpX63q8Amhgk8il3Sshenlora
         yeAXocPct3YVwI9AkPhHvtCsCxTz6II7fP6bhiovJdrL2/AIbLQlnqbHIlPyKsNAN3U1
         WKyUuO2u6ONMv3cWPJgVAgwz53WNeWopexO7Z4NMbWfANiugjyaJpSCH04UHTMwO1F5P
         2Cb+aXJH5fLUCCx48X0O30IuTjyPnvykI5SuQv2fDiXQeIodGbDajSTKstKSb7Epunvi
         +whg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481850; x=1758086650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rRoPn+JSPnq/N8b0n0aoT3NBEFjE2QHpMMdkB0MnauQ=;
        b=Rj5QS5dlG0zWO0QPMjcqnI6cF08m5z/8ec37bTWxNWvyaCMbDdsl30hw4/kSC5bGEt
         VFYV/cC/up1EZs9TmmAlA58TWcR2Heo2wX/IUhnN86jsArt+Yuc0gf6HydUFFvFUNfdX
         w3fiTqY0lgQNGqU1ciZjfC3dIM61Jiy5Ex05++NFFYAJI8XJTusumqOahgxXx9qmpFbL
         twZwQUv2HRVitDwqR1uoOxD5mycEcmbwysIuVFKRfUjWJDtKeDfCRPSnPAqbYnXMDvod
         A4MUzCsJRotq97sS5i9fz6T9DTSVMTqd10lw5s8XeqJHr7eCK+Jsi1Vh6xYI1hv4NzYM
         ps0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481850; x=1758086650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rRoPn+JSPnq/N8b0n0aoT3NBEFjE2QHpMMdkB0MnauQ=;
        b=ZWqXSUmy31ZPPYwa8U6kEyEryBWpVfHboi0sd7qbYY6dSs9ZPllnJEwJpbiW+nfYO8
         yF6shjOHdWl/GnO7vxPyh79MLIguaJDvWRcI/SLY+mdD1lhhhfps+cFX7Gd8Mh6RguQ9
         TqUvNdJEc1JUAKiEFqvEjdOcAJIQCvCeMaRuEvtZ1R5nctM99imHboNhC9nX2ZXXPpeF
         Jbys75vskS08/6teJSokVZyFZ3rA8+0lpQf3iY7EaaCtZ96IHL4tEQ9UmNLqV1TEdIJq
         0yrGOld0VzI/xZxpVG1+Xwq2tLrM77kMY+Q2XRsob/Xue7a9L32wUYWY+SmLOf6v8tzE
         WJbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfCe8qBmMnVedGsecOX6vC2PHuoOKMOMDBF7sO2BJaE4ZgfYi0yHD/vl4u7Q9ucpw/4cyzWA==@lfdr.de
X-Gm-Message-State: AOJu0Yw3ktf6NDf+2m3fa6oRxFBBFcpcNdW95m3R5eYSwosLfJ5E8k6w
	o6NjEzNBnAB3STp8AyRA6wFaUhhyGnOnR+GxwFoJW/UQ4FFfvRpwp/9T
X-Google-Smtp-Source: AGHT+IEfYrva/V9mxULdK1iV7kAx7oug0J2BbgmekVLedV5pHFGBgWeLQLzAK7c929MecR/dJ6B0Og==
X-Received: by 2002:a05:6e02:164c:b0:3ec:4b19:1cff with SMTP id e9e14a558f8ab-3fdfe0eca2bmr260385415ab.7.1757481850432;
        Tue, 09 Sep 2025 22:24:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcUSylt8MAeO04EYXhfM/uDivx2qCdApIpmHk+t2X3TCA==
Received: by 2002:a05:6e02:490b:b0:40a:24e:f416 with SMTP id
 e9e14a558f8ab-416908879a2ls1791835ab.2.-pod-prod-00-us-canary; Tue, 09 Sep
 2025 22:24:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbA0zKCvhNz18fhI1poUnJFfNgzwhAojUXmKGK9UgONIMFer+WhQHjVGNHz23Q0WqhssFKvKwuoEI=@googlegroups.com
X-Received: by 2002:a05:6602:2dc9:b0:887:601:c5f6 with SMTP id ca18e2360f4ac-88777a42dcbmr2303488139f.7.1757481849172;
        Tue, 09 Sep 2025 22:24:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481849; cv=none;
        d=google.com; s=arc-20240605;
        b=GeRMuHuRjkAoEo3CUuM2N+ml++oHe4P8F8r9u2A9/TbYWdA8rVNes/Az6UP1QsgdiP
         PTx41kAU59/GpZcsMH+hpK7rrsGJlX/0fYnh5tbVDtp/qkE+D5AnZEFbcb2f8yqCt7Nc
         E7loyjgFwuEUK5PyYjw4l+2bczz+3ZfbVAZId9CmJF2ZdPSsr5YvtcGZzc/w8FDAlV09
         M1uztv7NDPiloAuOHXGy0XtqYHsUrp0BYNALzs5ayS9FNBQSHQ2xFek6rRmlQtz4TMat
         j8fHwa14mestdNnhLG/U7TPK9uGyL4GMTfT5nwPWEN0pfa46rWugvAW+XxJ7CO79GmWg
         k3vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cftv6dbe1p8dhP2DYhCN2AZkHpit5y+1p22q3P/B8ik=;
        fh=AcKbIu6xzWe49GEOIbYfREUEwnfTxvK6m5VgNB+40jA=;
        b=OUhgq+4XmAriupc8sdkC/hxV6xvGoduI++yN3WYFOHnlv3Pq3ULlTHq8xRg3/m4gOj
         aQqS12xjIrQOtgmmWGHAbgP98E7nCJTVjPgTLBQ0Rw1dA7i2E+vLHPAHIkvwMPAvvfbK
         rYP/yYs91zprOh3XquXk+UeZcwmNwsEgOjQnnThjNSAbEKX4gR8u2jTY1l3dfLmY4ge9
         2yVQHPkKLE29piKsKywFAZwVYwz2FqSaZKuMYciKDcrI2a3oroNGKzNSpweSVvljGxcP
         e3bxmXsbCIkVPDx/jiMiHL174MqLUraa+jPGH5wuo8xKGvGDKA1J5PRoh8yyGmQbLvNJ
         JxIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=G1NP4nYi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8876f77c02bsi56623739f.4.2025.09.09.22.24.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:24:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b47052620a6so192969a12.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:24:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzksdn0t5O9Wb7tjTMqILm/ix5YThiuiFUGJIMwfaGr5DkbFXKGH+pexnlmxMh8G8y2wwv6Zv6T90=@googlegroups.com
X-Gm-Gg: ASbGnctA5ZJhX31+CEdqWDAL5QoJXmAJr/eTvX4L/gAtk/ZRNItUW5JxTHNYlQ2A2hu
	RY4wZV/1N870Npey7PHPgUf+ZlNd2o0TPtbZhwI3ynFZVdTm8pdOw1B44t1KKKt+WbKlqs97LLt
	QJf8HFuBicPwW7dor0zINGSd2Mvb1DO125zVyML6VOncg7FO7GpD+s35f/Zig59qpceEnA8ZcL2
	S1u+MS5l7z9EiTbjS0VIm4azYL5gWtOOzadwXloZ+C2xJtqJLoEkoPPvi8TQeQB70QpQ1X58XA/
	DSbkP2G6DiMY0EM06g/9T9SMf1eaTPbfUybWsqqNYMfHuVB2DRvjyau36s4bdvm8GsNuclk8JTu
	l6eT54qDVINeBdQzFU97SA2G09Yb/oIgoVg==
X-Received: by 2002:a17:903:986:b0:240:417d:8166 with SMTP id d9443c01a7336-251788fd271mr178360345ad.19.1757481848399;
        Tue, 09 Sep 2025 22:24:08 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.23.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:24:07 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 00/19] mm/ksw: Introduce real-time Kernel Stack Watch debugging tool
Date: Wed, 10 Sep 2025 13:23:09 +0800
Message-ID: <20250910052335.1151048-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=G1NP4nYi;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

This patch series introduces **KStackWatch**, a lightweight kernel debugging tool
for detecting kernel stack corruption in real time.

The motivation comes from scenarios where corruption occurs silently in one function
but manifests later as a crash in another. Using KASAN may not reproduce the issue due
to its heavy overhead. with no direct call trace linking the two. Such bugs are often
extremely hard to debug with existing tools.
I demonstrate this scenario in **test2 (silent corruption test)**.

KStackWatch works by combining a hardware breakpoint with kprobe and fprobe.
It can watch a stack canary or a selected local variable and detects the moment the
corruption actually occurs. This allows developers to pinpoint the real source rather
than only observing the final crash.

Key features include:

  - Lightweight overhead with minimal impact on bug reproducibility
  - Real-time detection of stack corruption
  - Simple configuration through `/proc/kstackwatch`
  - Support for recursive depth filter

To validate the approach, the patch includes a test module and a test script.

---
Changelog

V3:
  Main changes:
    * Use modify_wide_hw_breakpoint_local() (from Masami)
    * Add atomic flag to restrict /proc/kstackwatch to a single opener
    * Protect stack probe with an atomic PID flag
    * Handle CPU hotplug for watchpoints
    * Add preempt_disable/enable in ksw_watch_on_local_cpu()
    * Introduce const struct ksw_config *ksw_get_config(void) and use it
    * Switch to global watch_attr, remove struct watch_info
    * Validate local_var_len in parser()
    * Handle case when canary is not found
    * Use dump_stack() instead of show_regs() to allow module build

  Cleanups:
    * Reduce logging and comments
    * Format logs with KBUILD_MODNAME
    * Remove unused headers

  Documentation:
    * Add new document

V2:
  https://lore.kernel.org/all/20250904002126.1514566-1-wangjinchao600@gmail.com/
  * Make hardware breakpoint and stack operations architecture-independent.

V1:
  https://lore.kernel.org/all/20250828073311.1116593-1-wangjinchao600@gmail.com/
  Core Implementation
    *   Replaced kretprobe with fprobe for function exit hooking, as suggested
        by Masami Hiramatsu
    *   Introduced per-task depth logic to track recursion across scheduling
    *   Removed the use of workqueue for a more efficient corruption check
    *   Reordered patches for better logical flow
    *   Simplified and improved commit messages throughout the series
    *   Removed initial archcheck which should be improved later


  Testing and Architecture

    *   Replaced the multiple-thread test with silent corruption test
    *   Split self-tests into a separate patch to improve clarity.

  Maintenance
    *   Added a new entry for KStackWatch to the MAINTAINERS file.

RFC:
  https://lore.kernel.org/lkml/20250818122720.434981-1-wangjinchao600@gmail.com/
---

The series is structured as follows:

Jinchao Wang (18):
  x86/hw_breakpoint: introduce arch_reinstall_hw_breakpoint() for atomic
    context
  mm/ksw: add build system support
  mm/ksw: add ksw_config struct and parser
  mm/ksw: add /proc/kstackwatch interface
  mm/ksw: add HWBP pre-allocation
  mm/ksw: add atomic watch on/off operations
  mm/ksw: support CPU hotplug
  mm/ksw: add probe management helpers
  mm/ksw: resolve stack watch addr and len
  mm/ksw: add recursive depth tracking
  mm/ksw: manage start/stop of stack watching
  mm/ksw: add self-debug helpers
  mm/ksw: add test module
  mm/ksw: add stack overflow test
  mm/ksw: add silent corruption test case
  mm/ksw: add recursive stack corruption test
  tools/ksw: add test script
  docs: add KStackWatch document

Masami Hiramatsu (Google) (1):
  HWBP: Add modify_wide_hw_breakpoint_local() API

 Documentation/dev-tools/kstackwatch.rst |  94 ++++++++
 MAINTAINERS                             |   7 +
 arch/Kconfig                            |  10 +
 arch/x86/Kconfig                        |   1 +
 arch/x86/include/asm/hw_breakpoint.h    |   1 +
 arch/x86/kernel/hw_breakpoint.c         |  50 +++++
 include/linux/hw_breakpoint.h           |   6 +
 kernel/events/hw_breakpoint.c           |  36 ++++
 mm/Kconfig.debug                        |  21 ++
 mm/Makefile                             |   1 +
 mm/kstackwatch/Makefile                 |   8 +
 mm/kstackwatch/kernel.c                 | 239 ++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h            |  53 +++++
 mm/kstackwatch/stack.c                  | 276 ++++++++++++++++++++++++
 mm/kstackwatch/test.c                   | 259 ++++++++++++++++++++++
 mm/kstackwatch/watch.c                  | 205 ++++++++++++++++++
 tools/kstackwatch/kstackwatch_test.sh   |  40 ++++
 17 files changed, 1307 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/test.c
 create mode 100644 mm/kstackwatch/watch.c
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-1-wangjinchao600%40gmail.com.
